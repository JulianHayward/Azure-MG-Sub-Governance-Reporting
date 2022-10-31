function processManagedIdentities {
    Write-Host 'Processing Service Principals - Managed Identities'
    $startSPMI = Get-Date
    $script:servicePrincipalsOfTypeManagedIdentity = $htServicePrincipals.Keys.where( { $htServicePrincipals.($_).servicePrincipalType -eq 'ManagedIdentity' } )
    $script:servicePrincipalsOfTypeManagedIdentityCount = $servicePrincipalsOfTypeManagedIdentity.Count
    if ($servicePrincipalsOfTypeManagedIdentityCount -gt 0) {
        foreach ($sp in $servicePrincipalsOfTypeManagedIdentity) {
            $hlpSp = $htServicePrincipals.($sp)
            if ($hlpSp.alternativeNames -gt 0) {
                foreach ($usageentry in $hlpSp.alternativeNames) {
                    if ($usageentry -like '*/providers/Microsoft.Authorization/policyAssignments/*') {
                        $script:htManagedIdentityForPolicyAssignment.($hlpSp.Id) = @{}
                        $script:htManagedIdentityForPolicyAssignment.($hlpSp.Id).policyAssignmentId = $usageentry.ToLower()
                        $script:htPolicyAssignmentManagedIdentity.($usageentry.ToLower()) = @{}
                        $script:htPolicyAssignmentManagedIdentity.($usageentry.ToLower()).miObjectId = $hlpSp.id
                        if (-not $htManagedIdentityDisplayName.($hlpSp.displayName)) {
                            $script:htManagedIdentityDisplayName.("$($hlpSp.displayName)_$($usageentry.ToLower())") = $hlpSp
                        }
                    }
                }
            }
        }
    }
    $endSPMI = Get-Date
    Write-Host "Processing Service Principals - Managed Identities duration: $((New-TimeSpan -Start $startSPMI -End $endSPMI).TotalMinutes) minutes ($((New-TimeSpan -Start $startSPMI -End $endSPMI).TotalSeconds) seconds)"
}