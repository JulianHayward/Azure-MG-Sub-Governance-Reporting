function processMDfCCoverage {
    Write-Host '   Processing Defender Coverage'
    $start = Get-Date

    $htDefenderProps = @{}
    $htDefenderExtensions = @{}
    foreach ($x in $arrayDefenderPlans) {
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

    $arrayDefenderPlansNamesUnique = $arrayDefenderPlans.defenderPlan | Sort-Object -Unique
    $script:arrayDefenderPlansCoverage = [System.Collections.ArrayList]@()
    foreach ($defenderPlanName in $arrayDefenderPlansNamesUnique) {
        foreach ($defenderPlanEntry in $arrayDefenderPlans.where({ $_.defenderPlan -eq $defenderPlanName })) {
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

    $arrayDefenderPlanSpecificProperties = [System.Collections.ArrayList]@()
    $arrayDefenderPlanCommonProperties = @('plan', 'subscriptionId', 'subscriptionName', 'subscriptionMgPath', 'pricingTier', 'freeTrialRemainingTime')
    foreach ($plan in $arrayDefenderPlansCoverage) {
        $plan.Keys | ForEach-Object {
            if ($_ -notin $arrayDefenderPlanCommonProperties) {
                $null = $arrayDefenderPlanSpecificProperties.Add("$($plan.plan)_$($_)")
            }
        }
    }
    $arrayDefenderPlanSpecificPropertiesUnique = $arrayDefenderPlanSpecificProperties | Sort-Object -Unique

    $arrayDefenderPlansCoverageAll = [System.Collections.ArrayList]@()
    foreach ($entry in $arrayDefenderPlansCoverage) {
        $obj = [PSCustomObject]@{}
        foreach ($cprop in $arrayDefenderPlanCommonProperties) {
            $obj | Add-Member -MemberType NoteProperty -Name $cprop -Value $entry.($cprop)
        }
        foreach ($sprop in $arrayDefenderPlanSpecificPropertiesUnique) {
            if ($sprop -like "$($entry.plan)_*") {
                $obj | Add-Member -MemberType NoteProperty -Name $sprop -Value $entry.($sprop -replace "$($entry.plan)_", '' )
            }
            else {
                $obj | Add-Member -MemberType NoteProperty -Name $sprop -Value $null
            }
        }
        $null = $arrayDefenderPlansCoverageAll.Add($obj)
    }

    if (-not $NoCsvExport) {
        Write-Host "    Exporting MDfCCoverage CSV '$($outputPath)$($DirectorySeparatorChar)$($fileName)_MDfCCoverage.csv'"
        $arrayDefenderPlansCoverageAll | Sort-Object -Property plan, subscriptionName | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName)_MDfCCoverage.csv" -Delimiter "$csvDelimiter" -NoTypeInformation
    }

    $end = Get-Date
    Write-Host "    Defender Coverage processing duration: $((New-TimeSpan -Start $start -End $end).TotalMinutes) minutes ($((New-TimeSpan -Start $start -End $end).TotalSeconds) seconds)"
}