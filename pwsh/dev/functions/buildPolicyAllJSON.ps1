function buildPolicyAllJSON {
    Write-Host 'Creating PolicyAll JSON'
    $startPolicyAllJSON = Get-Date
    $htPolicyAndPolicySet = [ordered]@{}
    $htPolicyAndPolicySet.Policy = [ordered]@{}
    $htPolicyAndPolicySet.PolicySet = [ordered]@{}
    foreach ($policy in ($tenantPoliciesDetailed | Sort-Object -Property Type, ScopeMGLevel, PolicyDefinitionId)) {
        $htPolicyAndPolicySet.Policy.($policy.PolicyDefinitionId.ToLower()) = [ordered]@{}
        $htPolicyAndPolicySet.Policy.($policy.PolicyDefinitionId.ToLower()).PolicyType = $policy.Type
        $htPolicyAndPolicySet.Policy.($policy.PolicyDefinitionId.ToLower()).ScopeMGLevel = $policy.ScopeMGLevel
        $htPolicyAndPolicySet.Policy.($policy.PolicyDefinitionId.ToLower()).Scope = $policy.Scope
        $htPolicyAndPolicySet.Policy.($policy.PolicyDefinitionId.ToLower()).ScopeId = $policy.scopeId
        $htPolicyAndPolicySet.Policy.($policy.PolicyDefinitionId.ToLower()).PolicyDisplayName = $policy.PolicyDisplayName
        $htPolicyAndPolicySet.Policy.($policy.PolicyDefinitionId.ToLower()).PolicyDefinitionName = $policy.PolicyDefinitionName
        $htPolicyAndPolicySet.Policy.($policy.PolicyDefinitionId.ToLower()).PolicyDefinitionId = $policy.PolicyDefinitionId
        $htPolicyAndPolicySet.Policy.($policy.PolicyDefinitionId.ToLower()).PolicyEffect = $policy.PolicyEffect
        $htPolicyAndPolicySet.Policy.($policy.PolicyDefinitionId.ToLower()).PolicyCategory = $policy.PolicyCategory
        $htPolicyAndPolicySet.Policy.($policy.PolicyDefinitionId.ToLower()).UniqueAssignmentsCount = $policy.UniqueAssignmentsCount
        $htPolicyAndPolicySet.Policy.($policy.PolicyDefinitionId.ToLower()).UniqueAssignments = $policy.UniqueAssignments
        $htPolicyAndPolicySet.Policy.($policy.PolicyDefinitionId.ToLower()).UsedInPolicySetsCount = $policy.UsedInPolicySetsCount
        $htPolicyAndPolicySet.Policy.($policy.PolicyDefinitionId.ToLower()).UsedInPolicySets = $policy.UsedInPolicySet4JSON
        $htPolicyAndPolicySet.Policy.($policy.PolicyDefinitionId.ToLower()).CreatedOn = $policy.CreatedOn
        $htPolicyAndPolicySet.Policy.($policy.PolicyDefinitionId.ToLower()).CreatedBy = $policy.CreatedByJson
        $htPolicyAndPolicySet.Policy.($policy.PolicyDefinitionId.ToLower()).UpdatedOn = $policy.UpdatedOn
        $htPolicyAndPolicySet.Policy.($policy.PolicyDefinitionId.ToLower()).UpdatedBy = $policy.UpdatedByJson
        $htPolicyAndPolicySet.Policy.($policy.PolicyDefinitionId.ToLower()).JSON = $policy.Json
    }
    foreach ($policySet in ($tenantPolicySetsDetailed | Sort-Object -Property Type, ScopeMGLevel, PolicySetDefinitionId)) {
        $htPolicyAndPolicySet.PolicySet.($policySet.PolicySetDefinitionId.ToLower()) = [ordered]@{}
        $htPolicyAndPolicySet.PolicySet.($policySet.PolicySetDefinitionId.ToLower()).PolicySetType = $policy.Type
        $htPolicyAndPolicySet.PolicySet.($policySet.PolicySetDefinitionId.ToLower()).ScopeMGLevel = $policySet.ScopeMGLevel
        $htPolicyAndPolicySet.PolicySet.($policySet.PolicySetDefinitionId.ToLower()).Scope = $policySet.Scope
        $htPolicyAndPolicySet.PolicySet.($policySet.PolicySetDefinitionId.ToLower()).ScopeId = $policySet.scopeId
        $htPolicyAndPolicySet.PolicySet.($policySet.PolicySetDefinitionId.ToLower()).PolicySetDisplayName = $policySet.PolicySetDisplayName
        $htPolicyAndPolicySet.PolicySet.($policySet.PolicySetDefinitionId.ToLower()).PolicySetDefinitionName = $policySet.PolicySetDefinitionName
        $htPolicyAndPolicySet.PolicySet.($policySet.PolicySetDefinitionId.ToLower()).PolicySetDefinitionId = $policySet.PolicySetDefinitionId
        $htPolicyAndPolicySet.PolicySet.($policySet.PolicySetDefinitionId.ToLower()).PolicySetCategory = $policySet.PolicySetCategory
        $htPolicyAndPolicySet.PolicySet.($policySet.PolicySetDefinitionId.ToLower()).UniqueAssignmentsCount = $policySet.UniqueAssignmentsCount
        $htPolicyAndPolicySet.PolicySet.($policySet.PolicySetDefinitionId.ToLower()).UniqueAssignments = $policySet.UniqueAssignments
        $htPolicyAndPolicySet.PolicySet.($policySet.PolicySetDefinitionId.ToLower()).PoliciesUsedCount = $policySet.PoliciesUsedCount
        $htPolicyAndPolicySet.PolicySet.($policySet.PolicySetDefinitionId.ToLower()).PoliciesUsed = $policySet.PoliciesUsed4JSON
        $htPolicyAndPolicySet.PolicySet.($policySet.PolicySetDefinitionId.ToLower()).CreatedOn = $policySet.CreatedOn
        $htPolicyAndPolicySet.PolicySet.($policySet.PolicySetDefinitionId.ToLower()).CreatedBy = $policySet.CreatedByJson
        $htPolicyAndPolicySet.PolicySet.($policySet.PolicySetDefinitionId.ToLower()).UpdatedOn = $policySet.UpdatedOn
        $htPolicyAndPolicySet.PolicySet.($policySet.PolicySetDefinitionId.ToLower()).UpdatedBy = $policySet.UpdatedByJson
        $htPolicyAndPolicySet.PolicySet.($policySet.PolicySetDefinitionId.ToLower()).JSON = $policySet.Json
    }
    Write-Host " Exporting PolicyAll JSON '$($outputPath)$($DirectorySeparatorChar)$($fileName)_PolicyAll.json'"
    $htPolicyAndPolicySet | ConvertTo-JSON -Depth 99 | Set-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName)_PolicyAll.json" -Encoding utf8 -Force

    $endPolicyAllJSON = Get-Date
    Write-Host "Creating PolicyAll JSON duration: $((NEW-TIMESPAN -Start $startPolicyAllJSON -End $endPolicyAllJSON).TotalSeconds) seconds"
}
