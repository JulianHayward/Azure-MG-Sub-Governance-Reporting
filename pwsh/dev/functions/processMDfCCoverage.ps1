function processMDfCCoverage {
    Write-Host '   Processing Defender Coverage'
    $start = Get-Date

    $htDefenderProps = @{}
    $htDefenderExtensions = @{}
    $htDefenderPlansByName = @{}
    foreach ($x in $arrayDefenderPlans) {
        if (-not $htDefenderPlansByName.ContainsKey($x.defenderPlan)) {
            $htDefenderPlansByName[$x.defenderPlan] = [System.Collections.Generic.List[object]]::new()
        }
        $htDefenderPlansByName[$x.defenderPlan].Add($x)
        if (-not $htDefenderProps.($x.defenderPlan)) {
            $htDefenderProps.($x.defenderPlan) = [System.Collections.ArrayList]@()
        }
        if (-not $htDefenderExtensions.($x.defenderPlan)) {
            $htDefenderExtensions.($x.defenderPlan) = [System.Collections.ArrayList]@()
        }
        foreach ($noteprop in ($x.defenderPlanFull.properties | Get-Member).where({ $_.MemberType -eq 'NoteProperty' })) {
            if ($htDefenderProps.($x.defenderPlan) -notcontains $noteprop.Name) {
                $null = $htDefenderProps.($x.defenderPlan).Add($noteprop.Name)
            }
            if ($noteprop.Name -eq 'extensions') {
                foreach ($extension in $x.defenderPlanFull.properties.($noteprop.Name)) {
                    if ($htDefenderExtensions.($x.defenderPlan) -notcontains $extension.name) {
                        $null = $htDefenderExtensions.($x.defenderPlan).Add($extension.name)
                    }
                }
            }
        }
    }

    $arrayDefenderPlansNamesUnique = $htDefenderPlansByName.Keys | Sort-Object
    $script:arrayDefenderPlansCoverage = [System.Collections.ArrayList]@()
    foreach ($defenderPlanName in $arrayDefenderPlansNamesUnique) {
        foreach ($defenderPlanEntry in $htDefenderPlansByName[$defenderPlanName]) {
            $objDefenderPlan = [ordered]@{
                plan               = $defenderPlanEntry.defenderPlan
                subscriptionId     = $defenderPlanEntry.subscriptionId
                subscriptionName   = $defenderPlanEntry.subscriptionName
                subscriptionMgPath = $defenderPlanEntry.subscriptionMgPath
            }
            foreach ($prop in $htDefenderProps.($defenderPlanName)) {
                if ($prop -eq 'extensions') {
                    foreach ($extension in $htDefenderExtensions.($defenderPlanName)) {
                        $extensionObject = $defenderPlanEntry.defenderPlanFull.properties.extensions.where({ $_.name -eq $extension })
                        if ($extensionObject.count -gt 0) {
                            $objDefenderPlan.("ext_$($extension)") = $extensionObject.isEnabled
                            if ($defenderPlanName -eq 'StorageAccounts' -and $extension -eq 'OnUploadMalwareScanning') {
                                if ($extensionObject.additionalExtensionProperties.CapGBPerMonthPerStorageAccount) {
                                    $objDefenderPlan.("ext_$("$($extension)_CapGBPerMonthPerStorageAccount")") = $extensionObject.additionalExtensionProperties.CapGBPerMonthPerStorageAccount
                                }
                                else {
                                    $objDefenderPlan.("ext_$("$($extension)_CapGBPerMonthPerStorageAccount")") = $null
                                }
                            }
                        }
                        else {
                            $objDefenderPlan.("ext_$($extension)") = $null
                            if ($defenderPlanName -eq 'StorageAccounts' -and $extension -eq 'OnUploadMalwareScanning') {
                                $objDefenderPlan.("ext_$("$($extension)_CapGBPerMonthPerStorageAccount")") = $null
                            }
                        }
                    }
                }
                elseif ($prop -eq 'replacedBy') {
                    $objDefenderPlan.($prop) = $defenderPlanEntry.defenderPlanFull.properties.($prop) -join ';'
                }
                else {
                    $objDefenderPlan.($prop) = $defenderPlanEntry.defenderPlanFull.properties.($prop)
                }

                if ($defenderPlanName -eq 'VirtualMachines' -and $prop -eq 'subPlan') {
                    if ($defenderPlanEntry.defenderPlanFull.properties.($prop)) {
                        if ($htSecuritySettings.($defenderPlanEntry.subscriptionId).WDATP) {
                            $objDefenderPlan.('ext_MicrosoftDefenderforEndpoint') = ($htSecuritySettings.($defenderPlanEntry.subscriptionId).WDATP.properties.enabled).ToString()
                        }
                        else {
                            $objDefenderPlan.('ext_MicrosoftDefenderforEndpoint') = 'unknown'
                        }
                    }
                    else {
                        $objDefenderPlan.('ext_MicrosoftDefenderforEndpoint') = 'n/a'
                    }

                }
            }
            $null = $script:arrayDefenderPlansCoverage.Add($objDefenderPlan)
        }
    }

    # $tstsmp = Get-Date -Format 'yyyyMMdd_HHmmss'
    # $arrayDefenderPlansCoverage | ConvertTo-Json -Depth 99 > "c:\temp\defenderCoverage_Final_$($tstsmp).json"

    $htDefenderPlanSpecificProperties = @{}
    $arrayDefenderPlanCommonProperties = @('plan', 'subscriptionId', 'subscriptionName', 'subscriptionMgPath', 'pricingTier', 'freeTrialRemainingTime')
    foreach ($plan in $arrayDefenderPlansCoverage) {
        foreach ($key in $plan.Keys) {
            if ($key -notin $arrayDefenderPlanCommonProperties) {
                $htDefenderPlanSpecificProperties["$($plan.plan)_$($key)"] = $true
            }
        }
    }
    $arrayDefenderPlanSpecificPropertiesUnique = $htDefenderPlanSpecificProperties.Keys | Sort-Object

    $arrayDefenderPlansCoverageAll = [System.Collections.ArrayList]@()
    foreach ($entry in $arrayDefenderPlansCoverage) {
        $planPrefix = "$($entry.plan)_"
        $obj = [ordered]@{}
        foreach ($cprop in $arrayDefenderPlanCommonProperties) {
            $obj[$cprop] = $entry.($cprop)
        }
        foreach ($sprop in $arrayDefenderPlanSpecificPropertiesUnique) {
            if ($sprop.StartsWith($planPrefix)) {
                $obj[$sprop] = $entry[$sprop.Substring($planPrefix.Length)]
            }
            else {
                $obj[$sprop] = $null
            }
        }
        $null = $arrayDefenderPlansCoverageAll.Add([PSCustomObject]$obj)
    }

    if (-not $NoCsvExport) {
        Write-Host "    Exporting MDfCCoverage CSV '$($outputPath)$($DirectorySeparatorChar)$($fileName)_MDfCCoverage.csv'"
        $arrayDefenderPlansCoverageAll | Sort-Object -Property plan, subscriptionName | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName)_MDfCCoverage.csv" -Delimiter "$csvDelimiter" -NoTypeInformation
    }

    $end = Get-Date
    Write-Host "    Defender Coverage processing duration: $((New-TimeSpan -Start $start -End $end).TotalMinutes) minutes ($((New-TimeSpan -Start $start -End $end).TotalSeconds) seconds)"
}