$htTenantALZPolicies = @{}
foreach ($policy in $tenantCustomPolicies) {
    if ($policy.ALZ -eq 'true') {
        $htTenantALZPolicies.($policy.id -replace '.*/') = @{} 
    }
}

foreach ($alzPolicy in $alzPolicies.keys){

    if ($htTenantALZPolicies.($alzPolicy)){
        "ALZ"
    }
    else{
        "not"
    }
}


foreach ($alzPolicy in $alzPolicies){

}