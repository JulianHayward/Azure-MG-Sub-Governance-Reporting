function detectPolicyEffect {
    [CmdletBinding()]
    Param
    (
        [object]
        $policyDefinition
    )

    $htEffect = @{
        defaultValue  = 'n/a'
        allowedValues = 'n/a'
        fixedValue    = 'n/a'
    }
    if (-not [string]::IsNullOrWhiteSpace($policyDefinition.properties.policyRule.then.effect)) {
        if ($policyDefinition.properties.policyRule.then.effect -in $ValidPolicyEffects) {
            # $arrayeffect += "fixed: $($policyDefinition.properties.policyRule.then.effect)"
            # return $arrayeffect
            $htEffect.fixedValue = $policyDefinition.properties.policyRule.then.effect
            return $htEffect
        }
        else {
            $Regex = [Regex]::new("(?<=\[parameters\(')(.*)(?='\)\])")
            $Match = $Regex.Match($policyDefinition.properties.policyRule.then.effect)
            if ($Match.Success) {
                if (-not [string]::IsNullOrWhiteSpace($policyDefinition.properties.parameters.($Match.Value))) {

                    #defaultValue
                    if (($policyDefinition.properties.parameters.($Match.Value) | Get-Member).name -contains 'defaultvalue') {
                        if (-not [string]::IsNullOrWhiteSpace($policyDefinition.properties.parameters.($Match.Value).defaultValue)) {
                            if ($policyDefinition.properties.parameters.($Match.Value).defaultValue -in $ValidPolicyEffects) {
                                #$arrayeffect += "default: $($policyDefinition.properties.parameters.($Match.Value).defaultValue)"
                                $htEffect.defaultValue = $policyDefinition.properties.parameters.($Match.Value).defaultValue
                            }
                            else {
                                Write-Host "invalid defaultValue effect $($policyDefinition.properties.parameters.($Match.Value).defaultValue) - $($policyDefinition.name) ($($policyDefinition.properties.policyType))"
                            }
                        }
                        else {
                            Write-Host "defaultValue empty - $($policyDefinition.name) ($($policyDefinition.properties.policyType))"
                        }
                    }
                    else {
                        Write-Host "finding: Policy has no defaultvalue for effect: $($policyDefinition.id) ($($policyDefinition.properties.policyType))"
                    }
                    #allowedValues
                    if (($policyDefinition.properties.parameters.($Match.Value) | Get-Member).name -contains 'allowedValues') {
                        if (-not [string]::IsNullOrWhiteSpace($policyDefinition.properties.parameters.($Match.Value).allowedValues)) {
                            if ($policyDefinition.properties.parameters.($Match.Value).allowedValues.Count -gt 0) {
                                #Write-Host "allowedValues count $($policyDefinition.properties.parameters.($Match.Value).allowedValues) - $($policyDefinition.name) ($($policyDefinition.properties.policyType))"
                                $arrayAllowed = [System.Collections.ArrayList]@()
                                foreach ($allowedValue in $policyDefinition.properties.parameters.($Match.Value).allowedValues) {
                                    if ($allowedValue -in $ValidPolicyEffects) {
                                        $null = $arrayAllowed.Add($allowedValue)
                                    }
                                    else {
                                        Write-Host "invalid allowedValue effect $($allowedValue) - $($policyDefinition.name) ($($policyDefinition.properties.policyType))"
                                    }
                                }
                                #$arrayeffect += "allowed: $(($arrayAllowed | Sort-Object) -join ', ')"
                                $htEffect.allowedValues = ($arrayAllowed | Sort-Object) -join ','
                            }
                        }
                        else {
                            Write-Host "allowedValues empty - $($policyDefinition.name) ($($policyDefinition.properties.policyType))"
                        }
                    }
                    else {
                        Write-Host "no allowedValues- $($policyDefinition.name) ($($policyDefinition.properties.policyType))"
                    }

                }
                else {
                    Write-Host "unexpected - $($policyDefinition.name) ($($policyDefinition.properties.policyType))"
                }

                return $htEffect
            }
        }
    }
    else {
        Write-Host "no then effect - $($policyDefinition.name) ($($policyDefinition.properties.policyType))"
    }
    return $htEffect
}