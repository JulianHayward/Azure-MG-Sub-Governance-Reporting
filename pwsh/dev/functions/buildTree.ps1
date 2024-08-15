function buildTree($mgId, $prnt) {
    $getMg = $htEntities.values.where( { $_.type -eq 'Microsoft.Management/managementGroups' -and $_.id -eq $mgId })
    $childrenManagementGroups = $htEntities.values.where( { $_.type -eq 'Microsoft.Management/managementGroups' -and $_.parentId -eq "/providers/Microsoft.Management/managementGroups/$($getMg.Id)" })
    $mgNameValid = removeInvalidFileNameChars $getMg.Id
    $mgDisplayNameValid = removeInvalidFileNameChars $getMg.displayName
    $prntx = "$($prnt)$($DirectorySeparatorChar)$($mgNameValid) ($($mgDisplayNameValid))"
    if (-not (Test-Path -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($prntx)")) {
        $null = New-Item -Name $prntx -ItemType directory -Path $outputPath
    }

    if (-not $json.'ManagementGroups') {
        $json.'ManagementGroups' = [ordered]@{}
    }
    $json = $json.'ManagementGroups'.($getMg.Id) = [ordered]@{}
    $mgJson = $htJSON.ManagementGroups.($getMg.Id)
    foreach ($mgCap in $mgJson.keys) {
        $json.$mgCap = $mgJson.$mgCap
        if ($mgCap -eq 'PolicyDefinitionsCustom') {
            $mgCapShort = 'pd'
            foreach ($pdc in $mgJson.($mgCap).Keys) {
                $hlp = $mgJson.($mgCap).($pdc)
                if ([string]::IsNullOrEmpty($hlp.properties.displayName)) {
                    $displayName = 'noDisplayNameGiven'
                }
                else {
                    $displayName = removeInvalidFileNameChars $hlp.properties.displayName
                }
                $jsonConverted = $hlp.properties | ConvertTo-Json -Depth 99
                $jsonConverted | Set-Content -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($prntx)$($DirectorySeparatorChar)$($mgCapShort)_$($displayName) ($(removeInvalidFileNameChars $hlp.name)).json" -Encoding utf8
                $path = "$($JSONPath)$($DirectorySeparatorChar)Definitions$($DirectorySeparatorChar)PolicyDefinitions$($DirectorySeparatorChar)Custom$($DirectorySeparatorChar)Mg$($DirectorySeparatorChar)$($mgNameValid) ($($mgDisplayNameValid))"
                if (-not (Test-Path -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($path)")) {
                    $null = New-Item -Name $path -ItemType directory -Path $outputPath
                }
                $jsonConverted | Set-Content -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($path)$($DirectorySeparatorChar)$($displayName) ($(removeInvalidFileNameChars $hlp.name)).json" -Encoding utf8

                $jsonConvertedTracking = $hlp | ConvertTo-Json -Depth 99
                $pathTracking = "$($JSONPath)$($DirectorySeparatorChar)Definitions_tracking$($DirectorySeparatorChar)PolicyDefinitions$($DirectorySeparatorChar)Custom$($DirectorySeparatorChar)Mg$($DirectorySeparatorChar)$($mgNameValid)"
                if (-not (Test-Path -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($pathTracking)")) {
                    $null = New-Item -Name $pathTracking -ItemType directory -Path $outputPath
                }
                $jsonConvertedTracking | Set-Content -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($pathTracking)$($DirectorySeparatorChar)$(removeInvalidFileNameChars $hlp.name).json" -Encoding utf8
            }
        }
        if ($mgCap -eq 'PolicySetDefinitionsCustom') {
            $mgCapShort = 'psd'
            foreach ($psdc in $mgJson.($mgCap).Keys) {
                $hlp = $mgJson.($mgCap).($psdc)
                if ([string]::IsNullOrEmpty($hlp.properties.displayName)) {
                    $displayName = 'noDisplayNameGiven'
                }
                else {
                    $displayName = removeInvalidFileNameChars $hlp.properties.displayName
                }
                $jsonConverted = $hlp.properties | ConvertTo-Json -Depth 99
                $jsonConverted | Set-Content -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($prntx)$($DirectorySeparatorChar)$($mgCapShort)_$($displayName) ($(removeInvalidFileNameChars $hlp.name)).json" -Encoding utf8
                $path = "$($JSONPath)$($DirectorySeparatorChar)Definitions$($DirectorySeparatorChar)PolicySetDefinitions$($DirectorySeparatorChar)Custom$($DirectorySeparatorChar)Mg$($DirectorySeparatorChar)$($mgNameValid) ($($mgDisplayNameValid))"
                if (-not (Test-Path -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($path)")) {
                    $null = New-Item -Name $path -ItemType directory -Path $outputPath
                }
                $jsonConverted | Set-Content -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($path)$($DirectorySeparatorChar)$($displayName) ($(removeInvalidFileNameChars $hlp.name)).json" -Encoding utf8

                $jsonConvertedTracking = $hlp | ConvertTo-Json -Depth 99
                $pathTracking = "$($JSONPath)$($DirectorySeparatorChar)Definitions_tracking$($DirectorySeparatorChar)PolicySetDefinitions$($DirectorySeparatorChar)Custom$($DirectorySeparatorChar)Mg$($DirectorySeparatorChar)$($mgNameValid)"
                if (-not (Test-Path -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($pathTracking)")) {
                    $null = New-Item -Name $pathTracking -ItemType directory -Path $outputPath
                }
                $jsonConvertedTracking | Set-Content -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($pathTracking)$($DirectorySeparatorChar)$(removeInvalidFileNameChars $hlp.name).json" -Encoding utf8
            }
        }
        if ($mgCap -eq 'PolicyAssignments') {
            $mgCapShort = 'pa'
            foreach ($pa in $mgJson.($mgCap).Keys) {
                $hlp = $mgJson.($mgCap).($pa)
                if ([string]::IsNullOrEmpty($hlp.properties.displayName)) {
                    $displayName = 'noDisplayNameGiven'
                }
                else {
                    $displayName = removeInvalidFileNameChars $hlp.properties.displayName
                }
                $jsonConverted = $hlp | ConvertTo-Json -Depth 99
                $jsonConverted | Set-Content -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($prntx)$($DirectorySeparatorChar)$($mgCapShort)_$($displayName) ($(removeInvalidFileNameChars $hlp.name)).json" -Encoding utf8
                $path = "$($JSONPath)$($DirectorySeparatorChar)Assignments$($DirectorySeparatorChar)$($mgCap)$($DirectorySeparatorChar)Mg$($DirectorySeparatorChar)$($mgNameValid) ($($mgDisplayNameValid))"
                if (-not (Test-Path -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($path)")) {
                    $null = New-Item -Name $path -ItemType directory -Path $outputPath
                }
                $jsonConverted | Set-Content -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($path)$($DirectorySeparatorChar)$($displayName) ($(removeInvalidFileNameChars $hlp.name)).json" -Encoding utf8

                $pathTracking = "$($JSONPath)$($DirectorySeparatorChar)Assignments_tracking$($DirectorySeparatorChar)$($mgCap)$($DirectorySeparatorChar)Mg$($DirectorySeparatorChar)$($mgNameValid)"
                if (-not (Test-Path -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($pathTracking)")) {
                    $null = New-Item -Name $pathTracking -ItemType directory -Path $outputPath
                }
                $jsonConverted | Set-Content -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($pathTracking)$($DirectorySeparatorChar)$(removeInvalidFileNameChars $hlp.name).json" -Encoding utf8
            }
        }
        #marker
        if ($mgCap -eq 'RoleAssignments') {
            $mgCapShort = 'ra'
            foreach ($ra in $mgJson.($mgCap).Keys) {
                $hlp = $mgJson.($mgCap).($ra)
                if ($hlp.PIM -eq 'true') {
                    $pim = 'PIM_'
                }
                else {
                    $pim = ''
                }
                $jsonConverted = ($hlp | Select-Object -ExcludeProperty PIM) | ConvertTo-Json -Depth 99
                $jsonConverted | Set-Content -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($prntx)$($DirectorySeparatorChar)$($mgCapShort)_$($hlp.ObjectType)_$($pim)$($hlp.RoleAssignmentId -replace '.*/').json" -Encoding utf8
                $path = "$($JSONPath)$($DirectorySeparatorChar)Assignments$($DirectorySeparatorChar)$($mgCap)$($DirectorySeparatorChar)Mg$($DirectorySeparatorChar)$($mgNameValid) ($($mgDisplayNameValid))"
                if (-not (Test-Path -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($path)")) {
                    $null = New-Item -Name $path -ItemType directory -Path $outputPath
                }
                $jsonConverted | Set-Content -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($path)$($DirectorySeparatorChar)$($hlp.ObjectType)_$($pim)$($hlp.RoleAssignmentId -replace '.*/').json" -Encoding utf8
            }
        }

        if ($mgCap -eq 'Subscriptions') {
            foreach ($sub in $mgJson.($mgCap).Keys) {
                $subNameValid = removeInvalidFileNameChars $mgJson.($mgCap).($sub).SubscriptionName
                $subFolderName = "$($prntx)$($DirectorySeparatorChar)$($subNameValid) ($($sub))"
                $null = New-Item -Name $subFolderName -ItemType directory -Path $outputPath
                foreach ($subCap in $mgJson.($mgCap).($sub).Keys) {
                    if ($subCap -eq 'PolicyDefinitionsCustom') {
                        $subCapShort = 'pd'
                        foreach ($pdc in $mgJson.($mgCap).($sub).($subCap).Keys) {
                            $hlp = $mgJson.($mgCap).($sub).($subCap).($pdc)
                            if ([string]::IsNullOrEmpty($hlp.properties.displayName)) {
                                $displayName = 'noDisplayNameGiven'
                            }
                            else {
                                $displayName = removeInvalidFileNameChars $hlp.properties.displayName
                            }
                            $jsonConverted = $hlp.properties | ConvertTo-Json -Depth 99
                            $jsonConverted | Set-Content -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($subFolderName)$($DirectorySeparatorChar)$($subCapShort)_$($displayName) ($(removeInvalidFileNameChars $hlp.name)).json" -Encoding utf8
                            $path = "$($JSONPath)$($DirectorySeparatorChar)Definitions$($DirectorySeparatorChar)PolicyDefinitions$($DirectorySeparatorChar)Custom$($DirectorySeparatorChar)Sub$($DirectorySeparatorChar)$($subNameValid) ($($sub))"
                            if (-not (Test-Path -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($path)")) {
                                $null = New-Item -Name $path -ItemType directory -Path $outputPath
                            }
                            $jsonConverted | Set-Content -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($path)$($DirectorySeparatorChar)$($displayName) ($(removeInvalidFileNameChars $hlp.name)).json" -Encoding utf8

                            $jsonConvertedTracking = $hlp | ConvertTo-Json -Depth 99
                            $pathTracking = "$($JSONPath)$($DirectorySeparatorChar)Definitions_tracking$($DirectorySeparatorChar)PolicyDefinitions$($DirectorySeparatorChar)Custom$($DirectorySeparatorChar)Sub$($DirectorySeparatorChar)$($sub)"
                            if (-not (Test-Path -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($pathTracking)")) {
                                $null = New-Item -Name $pathTracking -ItemType directory -Path $outputPath
                            }
                            $jsonConvertedTracking | Set-Content -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($pathTracking)$($DirectorySeparatorChar)$(removeInvalidFileNameChars $hlp.name).json" -Encoding utf8
                        }
                    }
                    if ($subCap -eq 'PolicySetDefinitionsCustom') {
                        $subCapShort = 'psd'
                        foreach ($psdc in $mgJson.($mgCap).($sub).($subCap).Keys) {
                            $hlp = $mgJson.($mgCap).($sub).($subCap).($psdc)
                            if ([string]::IsNullOrEmpty($hlp.properties.displayName)) {
                                $displayName = 'noDisplayNameGiven'
                            }
                            else {
                                $displayName = removeInvalidFileNameChars $hlp.properties.displayName
                            }
                            $jsonConverted = $hlp.properties | ConvertTo-Json -Depth 99
                            $jsonConverted | Set-Content -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($subFolderName)$($DirectorySeparatorChar)$($subCapShort)_$($displayName) ($(removeInvalidFileNameChars $hlp.name)).json" -Encoding utf8
                            $path = "$($JSONPath)$($DirectorySeparatorChar)Definitions$($DirectorySeparatorChar)PolicySetDefinitions$($DirectorySeparatorChar)Custom$($DirectorySeparatorChar)Sub$($DirectorySeparatorChar)$($subNameValid) ($($sub))"
                            if (-not (Test-Path -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($path)")) {
                                $null = New-Item -Name $path -ItemType directory -Path $outputPath
                            }
                            $jsonConverted | Set-Content -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($path)$($DirectorySeparatorChar)$($displayName) ($(removeInvalidFileNameChars $hlp.name)).json" -Encoding utf8

                            $jsonConvertedTracking = $hlp | ConvertTo-Json -Depth 99
                            $pathTracking = "$($JSONPath)$($DirectorySeparatorChar)Definitions_tracking$($DirectorySeparatorChar)PolicySetDefinitions$($DirectorySeparatorChar)Custom$($DirectorySeparatorChar)Sub$($DirectorySeparatorChar)$($sub)"
                            if (-not (Test-Path -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($pathTracking)")) {
                                $null = New-Item -Name $pathTracking -ItemType directory -Path $outputPath
                            }
                            $jsonConvertedTracking | Set-Content -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($pathTracking)$($DirectorySeparatorChar)$(removeInvalidFileNameChars $hlp.name).json" -Encoding utf8
                        }
                    }
                    if ($subCap -eq 'PolicyAssignments') {
                        $subCapShort = 'pa'
                        foreach ($pa in $mgJson.($mgCap).($sub).($subCap).Keys) {
                            $hlp = $mgJson.($mgCap).($sub).($subCap).($pa)
                            if ([string]::IsNullOrEmpty($hlp.properties.displayName)) {
                                $displayName = 'noDisplayNameGiven'
                            }
                            else {
                                $displayName = removeInvalidFileNameChars $hlp.properties.displayName
                            }
                            $jsonConverted = $hlp | ConvertTo-Json -Depth 99
                            $jsonConverted | Set-Content -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($subFolderName)$($DirectorySeparatorChar)$($subCapShort)_$($displayName) ($(removeInvalidFileNameChars $hlp.name)).json" -Encoding utf8
                            $path = "$($JSONPath)$($DirectorySeparatorChar)Assignments$($DirectorySeparatorChar)$($subCap)$($DirectorySeparatorChar)Sub$($DirectorySeparatorChar)$($subNameValid) ($($sub))"
                            if (-not (Test-Path -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($path)")) {
                                $null = New-Item -Name $path -ItemType directory -Path $outputPath
                            }
                            $jsonConverted | Set-Content -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($path)$($DirectorySeparatorChar)$($displayName) ($(removeInvalidFileNameChars $hlp.name)).json" -Encoding utf8
                        }
                    }
                    #marker
                    if ($subCap -eq 'RoleAssignments') {
                        $subCapShort = 'ra'
                        foreach ($ra in $mgJson.($mgCap).($sub).($subCap).Keys) {
                            $hlp = $mgJson.($mgCap).($sub).($subCap).($ra)
                            if ($hlp.PIM -eq 'true') {
                                $pim = 'PIM_'
                            }
                            else {
                                $pim = ''
                            }
                            $jsonConverted = ($hlp | Select-Object -ExcludeProperty PIM) | ConvertTo-Json -Depth 99
                            $jsonConverted | Set-Content -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($subFolderName)$($DirectorySeparatorChar)$($subCapShort)_$($pim)$($hlp.ObjectType)_$($hlp.RoleAssignmentId -replace '.*/').json" -Encoding utf8
                            $path = "$($JSONPath)$($DirectorySeparatorChar)Assignments$($DirectorySeparatorChar)$($subCap)$($DirectorySeparatorChar)Sub$($DirectorySeparatorChar)$($subNameValid) ($($sub))"
                            if (-not (Test-Path -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($path)")) {
                                $null = New-Item -Name $path -ItemType directory -Path $outputPath
                            }
                            $jsonConverted | Set-Content -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($path)$($DirectorySeparatorChar)$($hlp.ObjectType)_$($pim)$($hlp.RoleAssignmentId -replace '.*/').json" -Encoding utf8
                        }
                    }

                    #RG Pol
                    if (-not $azAPICallConf['htParameters'].DoNotIncludeResourceGroupsOnPolicy) {
                        if (-not $JsonExportExcludeResourceGroups) {
                            if ($subCap -eq 'ResourceGroups') {
                                foreach ($rg in $mgJson.($mgCap).($sub).($subCap).Keys | Sort-Object) {
                                    if (-not (Test-Path -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($subFolderName)$($DirectorySeparatorChar)$($rg)")) {
                                        $null = New-Item -Name "$($subFolderName)$($DirectorySeparatorChar)$($rg)" -ItemType directory -Path "$($outputPath)"
                                    }
                                    foreach ($pa in $mgJson.($mgCap).($sub).($subCap).($rg).PolicyAssignments.keys) {
                                        $hlp = $mgJson.($mgCap).($sub).($subCap).($rg).PolicyAssignments.($pa)
                                        if ([string]::IsNullOrEmpty($hlp.properties.displayName)) {
                                            $displayName = 'noDisplayNameGiven'
                                        }
                                        else {
                                            $displayName = removeInvalidFileNameChars $hlp.properties.displayName
                                        }
                                        $jsonConverted = $hlp | ConvertTo-Json -Depth 99
                                        $jsonConverted | Set-Content -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($subFolderName)$($DirectorySeparatorChar)$($rg)$($DirectorySeparatorChar)pa_$($displayName) ($($hlp.name)).json" -Encoding utf8
                                        $path = "$($JSONPath)$($DirectorySeparatorChar)Assignments$($DirectorySeparatorChar)PolicyAssignments$($DirectorySeparatorChar)Sub$($DirectorySeparatorChar)$($subNameValid) ($($sub))$($DirectorySeparatorChar)$($rg)"
                                        if (-not (Test-Path -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($path)")) {
                                            $null = New-Item -Name $path -ItemType directory -Path $outputPath
                                        }
                                        $jsonConverted | Set-Content -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($path)$($DirectorySeparatorChar)$($displayName) ($($hlp.name)).json" -Encoding utf8
                                    }
                                }
                            }
                        }
                    }

                    #RG RoleAss
                    #marker
                    if (-not $azAPICallConf['htParameters'].DoNotIncludeResourceGroupsAndResourcesOnRBAC) {
                        if (-not $JsonExportExcludeResourceGroups) {
                            if ($subCap -eq 'ResourceGroups') {
                                foreach ($rg in $mgJson.($mgCap).($sub).($subCap).Keys | Sort-Object) {
                                    if (-not (Test-Path -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($subFolderName)$($DirectorySeparatorChar)$($rg)")) {
                                        $null = New-Item -Name "$($subFolderName)$($DirectorySeparatorChar)$($rg)" -ItemType directory -Path "$($outputPath)"
                                    }
                                    foreach ($ra in $mgJson.($mgCap).($sub).($subCap).($rg).RoleAssignments.keys) {
                                        $hlp = $mgJson.($mgCap).($sub).($subCap).($rg).RoleAssignments.($ra)
                                        if ($hlp.PIM -eq 'true') {
                                            $pim = 'PIM_'
                                        }
                                        else {
                                            $pim = ''
                                        }
                                        $jsonConverted = ($hlp | Select-Object -ExcludeProperty PIM) | ConvertTo-Json -Depth 99
                                        $jsonConverted | Set-Content -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($subFolderName)$($DirectorySeparatorChar)$($rg)$($DirectorySeparatorChar)ra_$($hlp.ObjectType)_$($pim)$($hlp.RoleAssignmentId -replace '.*/').json" -Encoding utf8
                                        $path = "$($JSONPath)$($DirectorySeparatorChar)Assignments$($DirectorySeparatorChar)RoleAssignments$($DirectorySeparatorChar)Sub$($DirectorySeparatorChar)$($subNameValid) ($($sub))$($DirectorySeparatorChar)$($rg)"
                                        if (-not (Test-Path -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($path)")) {
                                            $null = New-Item -Name $path -ItemType directory -Path $outputPath
                                        }
                                        $jsonConverted | Set-Content -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($path)$($DirectorySeparatorChar)$($hlp.ObjectType)_$($pim)$($hlp.RoleAssignmentId -replace '.*/').json" -Encoding utf8
                                    }
                                    #res
                                    if (-not $JsonExportExcludeResources) {

                                        foreach ($res in $mgJson.($mgCap).($sub).($subCap).($rg).Resources.keys) {
                                            if (-not (Test-Path -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($subFolderName)$($DirectorySeparatorChar)$($rg)$($DirectorySeparatorChar)$($res)")) {
                                                $null = New-Item -Name "$($subFolderName)$($DirectorySeparatorChar)$($rg)$($DirectorySeparatorChar)$($res)" -ItemType directory -Path "$($outputPath)"
                                            }
                                            foreach ($ra in $mgJson.($mgCap).($sub).($subCap).($rg).Resources.($res).RoleAssignments.keys) {
                                                $hlp = $mgJson.($mgCap).($sub).($subCap).($rg).Resources.($res).RoleAssignments.($ra)
                                                if ($hlp.PIM -eq 'true') {
                                                    $pim = 'PIM_'
                                                }
                                                else {
                                                    $pim = ''
                                                }
                                                $jsonConverted = ($hlp | Select-Object -ExcludeProperty PIM) | ConvertTo-Json -Depth 99
                                                $jsonConverted | Set-Content -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($subFolderName)$($DirectorySeparatorChar)$($rg)$($DirectorySeparatorChar)$($res)$($DirectorySeparatorChar)ra_$($hlp.ObjectType)_$($pim)$($hlp.RoleAssignmentId -replace '.*/').json" -Encoding utf8
                                                $path = "$($JSONPath)$($DirectorySeparatorChar)Assignments$($DirectorySeparatorChar)RoleAssignments$($DirectorySeparatorChar)Sub$($DirectorySeparatorChar)$($subNameValid) ($($sub))$($DirectorySeparatorChar)$($rg)$($DirectorySeparatorChar)$($res)"
                                                if (-not (Test-Path -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($path)")) {
                                                    $null = New-Item -Name $path -ItemType directory -Path $outputPath
                                                }
                                                $jsonConverted | Set-Content -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($path)$($DirectorySeparatorChar)$($hlp.ObjectType)_$($pim)$($hlp.RoleAssignmentId -replace '.*/').json" -Encoding utf8
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if ($childrenManagementGroups.Count -eq 0) {
        $json.'ManagementGroups' = @{}
    }
    else {
        foreach ($childMg in $childrenManagementGroups | Sort-Object -Property Id) {
            buildTree -mgId $childMg.Id -json $json -prnt $prntx
        }
    }
}