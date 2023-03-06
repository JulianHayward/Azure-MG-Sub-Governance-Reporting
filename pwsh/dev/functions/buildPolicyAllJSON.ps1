function buildPolicyAllJSON {
    Write-Host 'Creating PolicyAll JSON'
    $startPolicyAllJSON = Get-Date
    $htPolicyAndPolicySet = [ordered]@{}
    $htPolicyAndPolicySet.Policy = [ordered]@{}
    $htPolicyAndPolicySet.PolicySet = [ordered]@{}
    $htPolicyAndPolicySet.PolicyAssignment = [ordered]@{}
    foreach ($policy in ($tenantPoliciesDetailed | Sort-Object -Property Type, ScopeMGLevel, PolicyDefinitionId)) {
        $htPolicyAndPolicySet.Policy.($policy.PolicyDefinitionId.ToLower()) = [ordered]@{
            PolicyType             = $policy.Type
            ScopeMGLevel           = $policy.ScopeMGLevel
            Scope                  = $policy.Scope
            ScopeId                = $policy.scopeId
            PolicyDisplayName      = $policy.PolicyDisplayName
            PolicyDefinitionName   = $policy.PolicyDefinitionName
            PolicyDefinitionId     = $policy.PolicyDefinitionId
            PolicyEffect           = $policy.PolicyEffect
            PolicyCategory         = $policy.PolicyCategory
            UniqueAssignmentsCount = $policy.UniqueAssignmentsCount
            UniqueAssignments      = $policy.UniqueAssignments
            UsedInPolicySetsCount  = $policy.UsedInPolicySetsCount
            UsedInPolicySets       = $policy.UsedInPolicySet4JSON
            CreatedOn              = $policy.CreatedOn
            CreatedBy              = $policy.CreatedByJson
            UpdatedOn              = $policy.UpdatedOn
            UpdatedBy              = $policy.UpdatedByJson
            JSON                   = $policy.Json
        }
    }
    foreach ($policySet in ($tenantPolicySetsDetailed | Sort-Object -Property Type, ScopeMGLevel, PolicySetDefinitionId)) {
        $htPolicyAndPolicySet.PolicySet.($policySet.PolicySetDefinitionId.ToLower()) = [ordered]@{
            PolicySetType           = $policySet.Type
            ScopeMGLevel            = $policySet.ScopeMGLevel
            Scope                   = $policySet.Scope
            ScopeId                 = $policySet.scopeId
            PolicySetDisplayName    = $policySet.PolicySetDisplayName
            PolicySetDefinitionName = $policySet.PolicySetDefinitionName
            PolicySetDefinitionId   = $policySet.PolicySetDefinitionId
            PolicySetCategory       = $policySet.PolicySetCategory
            UniqueAssignmentsCount  = $policySet.UniqueAssignmentsCount
            UniqueAssignments       = $policySet.UniqueAssignments
            PoliciesUsedCount       = $policySet.PoliciesUsedCount
            PoliciesUsed            = $policySet.PoliciesUsed4JSON
            CreatedOn               = $policySet.CreatedOn
            CreatedBy               = $policySet.CreatedByJson
            UpdatedOn               = $policySet.UpdatedOn
            UpdatedBy               = $policySet.UpdatedByJson
            JSON                    = $policySet.Json
        }
    }
    foreach ($key in $htCacheAssignmentsPolicy.keys | Sort-Object) {
        $htPolicyAndPolicySet.PolicyAssignment.($key.ToLower()) = $htCacheAssignmentsPolicy.($key).Assignment
    }
    Write-Host " Exporting PolicyAll JSON '$($outputPath)$($DirectorySeparatorChar)$($fileName)_PolicyAll.json'"
    $htPolicyAndPolicySet | ConvertTo-Json -Depth 99 | Set-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName)_PolicyAll.json" -Encoding utf8 -Force

    $endPolicyAllJSON = Get-Date
    Write-Host "Creating PolicyAll JSON duration: $((New-TimeSpan -Start $startPolicyAllJSON -End $endPolicyAllJSON).TotalSeconds) seconds"
}
