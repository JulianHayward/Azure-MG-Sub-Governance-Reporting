function buildPolicyAllJSON {
    Write-Host 'Creating PolicyAll JSON'
    $startPolicyAllJSON = Get-Date
    $policyAllJsonPath = "$($outputPath)$($DirectorySeparatorChar)$($fileName)_PolicyAll.json"
    Write-Host " Exporting PolicyAll JSON '$($policyAllJsonPath)'"

    #entries are serialized and streamed one at a time - collecting them all and running a single ConvertTo-Json over the result peaked at several GB and got the process OOM killed
    $streamWriter = [System.IO.StreamWriter]::new($policyAllJsonPath, $false, [System.Text.UTF8Encoding]::new($false))
    try {
        $streamWriter.Write("{`n  `"Policy`": {")
        $countPolicy = 0
        foreach ($policy in ($tenantPoliciesDetailed | Sort-Object -Property Type, ScopeMGLevel, PolicyDefinitionId)) {
            $policyEntry = [ordered]@{
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
            if ($countPolicy -gt 0) {
                $streamWriter.Write(',')
            }
            #every line but the first is shifted to the indentation the entry has inside the document
            $streamWriter.Write("`n    $($policy.PolicyDefinitionId.ToLower() | ConvertTo-Json): $((($policyEntry | ConvertTo-Json -Depth 99) -split '\r?\n') -join "`n    ")")
            $countPolicy++
        }
        if ($countPolicy -gt 0) {
            $streamWriter.Write("`n  ")
        }

        $streamWriter.Write("},`n  `"PolicySet`": {")
        $countPolicySet = 0
        foreach ($policySet in ($tenantPolicySetsDetailed | Sort-Object -Property Type, ScopeMGLevel, PolicySetDefinitionId)) {
            $policySetEntry = [ordered]@{
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
            if ($countPolicySet -gt 0) {
                $streamWriter.Write(',')
            }
            $streamWriter.Write("`n    $($policySet.PolicySetDefinitionId.ToLower() | ConvertTo-Json): $((($policySetEntry | ConvertTo-Json -Depth 99) -split '\r?\n') -join "`n    ")")
            $countPolicySet++
        }
        if ($countPolicySet -gt 0) {
            $streamWriter.Write("`n  ")
        }

        $streamWriter.Write("},`n  `"PolicyAssignment`": {")
        $countPolicyAssignment = 0
        foreach ($key in $htCacheAssignmentsPolicy.keys | Sort-Object) {
            if ($countPolicyAssignment -gt 0) {
                $streamWriter.Write(',')
            }
            $streamWriter.Write("`n    $($key.ToLower() | ConvertTo-Json): $((($htCacheAssignmentsPolicy.($key).Assignment | ConvertTo-Json -Depth 99) -split '\r?\n') -join "`n    ")")
            $countPolicyAssignment++
        }
        if ($countPolicyAssignment -gt 0) {
            $streamWriter.Write("`n  ")
        }

        $streamWriter.Write("}`n}`n")
    }
    finally {
        $streamWriter.Dispose()
    }

    $endPolicyAllJSON = Get-Date
    Write-Host "Creating PolicyAll JSON duration: $((New-TimeSpan -Start $startPolicyAllJSON -End $endPolicyAllJSON).TotalSeconds) seconds"
}
