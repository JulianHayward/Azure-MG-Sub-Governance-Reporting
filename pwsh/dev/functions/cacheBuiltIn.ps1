function cacheBuiltIn {
    $startDefinitionsCaching = Get-Date
    Write-Host 'Caching built-in Policy and RBAC Role definitions'

    $arrayBuiltInCaching = @('PolicyDefinitions', 'PolicyDefinitionsStatic', 'PolicySetDefinitions', 'RoleDefinitions')

    $arrayBuiltInCaching | ForEach-Object -Parallel {

        $builtInCapability = $_
        #fromOtherFunctions
        $azAPICallConf = $using:azAPICallConf
        $scriptPath = $using:ScriptPath
        #Array&HTs
        $htCacheDefinitionsPolicy = $using:htCacheDefinitionsPolicy
        $htCacheDefinitionsPolicySet = $using:htCacheDefinitionsPolicySet
        $htCacheDefinitionsRole = $using:htCacheDefinitionsRole
        $ValidPolicyEffects = $using:ValidPolicyEffects
        $htHashesBuiltInPolicy = $using:htHashesBuiltInPolicy
        #vars
        $ARMLocation = $using:ARMLocation
        $ignoreARMLocation = $using:ignoreARMLocation
        #functions
        $function:detectPolicyEffect = $using:funcDetectPolicyEffect
        $function:getPolicyHash = $using:funcGetPolicyHash

        if ($builtInCapability -eq 'PolicyDefinitions') {
            $currentTask = 'Caching built-in Policy definitions'
            Write-Host " $currentTask"
            $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/providers/Microsoft.Authorization/policyDefinitions?api-version=2021-06-01&`$filter=policyType eq 'BuiltIn'"
            $method = 'GET'
            $requestPolicyDefinitionAPI = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask

            Write-Host " $($requestPolicyDefinitionAPI.Count) built-in Policy definitions returned"
            $builtinPolicyDefinitions = $requestPolicyDefinitionAPI.where( { $_.properties.policyType -eq 'BuiltIn' } )

            foreach ($builtinPolicyDefinition in $builtinPolicyDefinitions) {
                $script:htCacheDefinitionsPolicy.(($builtinPolicyDefinition.Id).ToLower()) = @{
                    Id                     = ($builtinPolicyDefinition.Id).ToLower()
                    ScopeMGLevel           = ''
                    Scope                  = 'n/a'
                    ScopeMgSub             = 'n/a'
                    ScopeId                = 'n/a'
                    DisplayName            = $builtinPolicyDefinition.Properties.displayname
                    Name                   = $builtinPolicyDefinition.Name
                    Description            = $builtinPolicyDefinition.Properties.description
                    Type                   = $builtinPolicyDefinition.Properties.policyType
                    Category               = $builtinPolicyDefinition.Properties.metadata.category
                    Version                = $builtinPolicyDefinition.Properties.metadata.version
                    PolicyDefinitionId     = ($builtinPolicyDefinition.Id).ToLower()
                    LinkToAzAdvertizer     = "<a class=`"externallink`" href=`"https://www.azadvertizer.net/azpolicyadvertizer/$(($builtinPolicyDefinition.Id -replace '.*/')).html`" target=`"_blank`" rel=`"noopener`">$($builtinPolicyDefinition.Properties.displayname)</a>"
                    ALZ                    = $false
                    ALZState               = ''
                    ALZLatestVer           = ''
                    ALZIdentificationLevel = ''
                    ALZPolicyName          = ''
                }

                if ($builtinPolicyDefinition.Properties.metadata.deprecated -eq $true -or $builtinPolicyDefinition.Properties.displayname -like "``[Deprecated``]*") {
                    $script:htCacheDefinitionsPolicy.(($builtinPolicyDefinition.Id).ToLower()).Deprecated = $builtinPolicyDefinition.Properties.metadata.deprecated
                }
                else {
                    $script:htCacheDefinitionsPolicy.(($builtinPolicyDefinition.Id).ToLower()).Deprecated = $false
                }
                if ($builtinPolicyDefinition.Properties.metadata.preview -eq $true -or $builtinPolicyDefinition.Properties.displayname -like "``[*Preview``]*") {
                    $script:htCacheDefinitionsPolicy.(($builtinPolicyDefinition.Id).ToLower()).Preview = $builtinPolicyDefinition.Properties.metadata.preview
                }
                else {
                    $script:htCacheDefinitionsPolicy.(($builtinPolicyDefinition.Id).ToLower()).Preview = $false
                }
                #region effect
                $htEffectDetected = detectPolicyEffect -policyDefinition $builtinPolicyDefinition
                $script:htCacheDefinitionsPolicy.(($builtinPolicyDefinition.Id).ToLower()).effectDefaultValue = $htEffectDetected.defaultValue
                $script:htCacheDefinitionsPolicy.(($builtinPolicyDefinition.Id).ToLower()).effectAllowedValue = $htEffectDetected.allowedValues
                $script:htCacheDefinitionsPolicy.(($builtinPolicyDefinition.Id).ToLower()).effectFixedValue = $htEffectDetected.fixedValue
                #endregion effect
                $script:htCacheDefinitionsPolicy.(($builtinPolicyDefinition.Id).ToLower()).Json = $builtinPolicyDefinition

                if (-not [string]::IsNullOrWhiteSpace($builtinPolicyDefinition.properties.policyRule.then.details.roleDefinitionIds)) {
                    $script:htCacheDefinitionsPolicy.(($builtinPolicyDefinition.Id).ToLower()).RoleDefinitionIds = $builtinPolicyDefinition.properties.policyRule.then.details.roleDefinitionIds
                }
                else {
                    $script:htCacheDefinitionsPolicy.(($builtinPolicyDefinition.Id).ToLower()).RoleDefinitionIds = 'n/a'
                }

                #hashes for parity builtin/custom
                # $script:htHashesBuiltInPolicy.(($builtinPolicyDefinition.Id).ToLower()) = @{
                #     policyRuleHash = getPolicyHash -object ($builtinPolicyDefinition.properties.policyRule | ConvertTo-Json -Depth 99)
                # }
                $policyRuleHash = (getPolicyHash -json ($builtinPolicyDefinition.properties.policyRule | ConvertTo-Json -Depth 99))
                if (-not $htHashesBuiltInPolicy.($policyRuleHash)) {
                    $script:htHashesBuiltInPolicy.($policyRuleHash) = @{
                        Policies = [System.Collections.ArrayList]@()
                    }
                    $null = $script:htHashesBuiltInPolicy.($policyRuleHash).Policies.Add(($builtinPolicyDefinition.Id).ToLower())
                }
                else {
                    #Write-Host "$($builtinPolicyDefinition.name) $($policyRuleHash) already exists"
                    $null = $script:htHashesBuiltInPolicy.($policyRuleHash).Policies.Add(($builtinPolicyDefinition.Id).ToLower())
                    #$htHashesBuiltInPolicy.($policyRuleHash).Policies.Count
                }
            }
            Write-Host " $($htHashesBuiltInPolicy.Keys.Count) unique Policy rule hashes for built-in Policy definitions"
        }

        if ($builtInCapability -eq 'PolicyDefinitionsStatic') {
            $currentTask = 'Caching static Policy definitions'
            Write-Host " $currentTask"
            $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/providers/Microsoft.Authorization/policyDefinitions?api-version=2021-06-01&`$filter=policyType eq 'Static'"
            $method = 'GET'
            $requestPolicyDefinitionAPI = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask

            Write-Host " $($requestPolicyDefinitionAPI.Count) static Policy definitions returned"
            $staticPolicyDefinitions = $requestPolicyDefinitionAPI.where( { $_.properties.policyType -eq 'Static' } )

            foreach ($staticPolicyDefinition in $staticPolicyDefinitions) {
                $script:htCacheDefinitionsPolicy.(($staticPolicyDefinition.Id).ToLower()) = @{
                    Id                     = ($staticPolicyDefinition.Id).ToLower()
                    ScopeMGLevel           = ''
                    Scope                  = 'n/a'
                    ScopeMgSub             = 'n/a'
                    ScopeId                = 'n/a'
                    DisplayName            = $staticPolicyDefinition.Properties.displayname
                    Name                   = $staticPolicyDefinition.Name
                    Description            = $staticPolicyDefinition.Properties.description
                    Type                   = $staticPolicyDefinition.Properties.policyType
                    Category               = $staticPolicyDefinition.Properties.metadata.category
                    Version                = $staticPolicyDefinition.Properties.metadata.version
                    PolicyDefinitionId     = ($staticPolicyDefinition.Id).ToLower()
                    LinkToAzAdvertizer     = "<a class=`"externallink`" href=`"https://www.azadvertizer.net/azpolicyadvertizer/$(($staticPolicyDefinition.Id -replace '.*/')).html`" target=`"_blank`" rel=`"noopener`">$($staticPolicyDefinition.Properties.displayname)</a>"
                    ALZ                    = $false
                    ALZState               = ''
                    ALZLatestVer           = ''
                    ALZIdentificationLevel = ''
                    ALZPolicyName          = ''
                }


                if ($staticPolicyDefinition.Properties.metadata.deprecated -eq $true -or $staticPolicyDefinition.Properties.displayname -like "``[Deprecated``]*") {
                    $script:htCacheDefinitionsPolicy.(($staticPolicyDefinition.Id).ToLower()).Deprecated = $staticPolicyDefinition.Properties.metadata.deprecated
                }
                else {
                    $script:htCacheDefinitionsPolicy.(($staticPolicyDefinition.Id).ToLower()).Deprecated = $false
                }
                if ($staticPolicyDefinition.Properties.metadata.preview -eq $true -or $staticPolicyDefinition.Properties.displayname -like "``[*Preview``]*") {
                    $script:htCacheDefinitionsPolicy.(($staticPolicyDefinition.Id).ToLower()).Preview = $staticPolicyDefinition.Properties.metadata.preview
                }
                else {
                    $script:htCacheDefinitionsPolicy.(($staticPolicyDefinition.Id).ToLower()).Preview = $false
                }
                #region effect
                $htEffectDetected = detectPolicyEffect -policyDefinition $staticPolicyDefinition
                $script:htCacheDefinitionsPolicy.(($staticPolicyDefinition.Id).ToLower()).effectDefaultValue = $htEffectDetected.defaultValue
                $script:htCacheDefinitionsPolicy.(($staticPolicyDefinition.Id).ToLower()).effectAllowedValue = $htEffectDetected.allowedValues
                $script:htCacheDefinitionsPolicy.(($staticPolicyDefinition.Id).ToLower()).effectFixedValue = $htEffectDetected.fixedValue
                #endregion effect
                $script:htCacheDefinitionsPolicy.(($staticPolicyDefinition.Id).ToLower()).Json = $staticPolicyDefinition

                if (-not [string]::IsNullOrWhiteSpace($staticPolicyDefinition.properties.policyRule.then.details.roleDefinitionIds)) {
                    $script:htCacheDefinitionsPolicy.(($staticPolicyDefinition.Id).ToLower()).RoleDefinitionIds = $staticPolicyDefinition.properties.policyRule.then.details.roleDefinitionIds
                }
                else {
                    $script:htCacheDefinitionsPolicy.(($staticPolicyDefinition.Id).ToLower()).RoleDefinitionIds = 'n/a'
                }
            }
        }

        if ($builtInCapability -eq 'PolicySetDefinitions') {

            $currentTask = 'Caching built-in PolicySet definitions'
            Write-Host " $currentTask"
            $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/providers/Microsoft.Authorization/policySetDefinitions?api-version=2021-06-01&`$filter=policyType eq 'BuiltIn'"
            $method = 'GET'
            $requestPolicySetDefinitionAPI = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask

            $builtinPolicySetDefinitions = $requestPolicySetDefinitionAPI.where( { $_.properties.policyType -eq 'BuiltIn' } )
            Write-Host " $($requestPolicySetDefinitionAPI.Count) built-in PolicySet definitions returned"
            foreach ($builtinPolicySetDefinition in $builtinPolicySetDefinitions) {
                $script:htCacheDefinitionsPolicySet.(($builtinPolicySetDefinition.Id).ToLower()) = @{
                    Id                     = ($builtinPolicySetDefinition.Id).ToLower()
                    ScopeMGLevel           = ''
                    Scope                  = 'n/a'
                    ScopeMgSub             = 'n/a'
                    ScopeId                = 'n/a'
                    DisplayName            = $builtinPolicySetDefinition.Properties.displayname
                    Name                   = $builtinPolicySetDefinition.Name
                    Description            = $builtinPolicySetDefinition.Properties.description
                    Type                   = $builtinPolicySetDefinition.Properties.policyType
                    Category               = $builtinPolicySetDefinition.Properties.metadata.category
                    Version                = $builtinPolicySetDefinition.Properties.metadata.version
                    PolicyDefinitionId     = ($builtinPolicySetDefinition.Id).ToLower()
                    LinkToAzAdvertizer     = "<a class=`"externallink`" href=`"https://www.azadvertizer.net/azpolicyinitiativesadvertizer/$(($builtinPolicySetDefinition.Id -replace '.*/')).html`" target=`"_blank`" rel=`"noopener`">$($builtinPolicySetDefinition.Properties.displayname)</a>"
                    ALZ                    = $false
                    ALZState               = ''
                    ALZLatestVer           = ''
                    ALZIdentificationLevel = ''
                    ALZPolicySetName       = ''
                }
                $htPolicySetPolicyRefIds = @{}
                $arrayPolicySetPolicyIdsToLower = foreach ($policySetPolicy in $builtinPolicySetDefinition.properties.policydefinitions) {
                    ($policySetPolicy.policyDefinitionId).ToLower()
                    $htPolicySetPolicyRefIds.($policySetPolicy.policyDefinitionReferenceId) = ($policySetPolicy.policyDefinitionId)
                }
                $script:htCacheDefinitionsPolicySet.(($builtinPolicySetDefinition.Id).ToLower()).PolicySetPolicyIds = $arrayPolicySetPolicyIdsToLower
                $script:htCacheDefinitionsPolicySet.(($builtinPolicySetDefinition.Id).ToLower()).PolicySetPolicyRefIds = $htPolicySetPolicyRefIds
                if ($builtinPolicySetDefinition.Properties.metadata.deprecated -eq $true -or $builtinPolicySetDefinition.Properties.displayname -like "``[Deprecated``]*") {
                    $script:htCacheDefinitionsPolicySet.(($builtinPolicySetDefinition.Id).ToLower()).Deprecated = $builtinPolicySetDefinition.Properties.metadata.deprecated
                }
                else {
                    $script:htCacheDefinitionsPolicySet.(($builtinPolicySetDefinition.Id).ToLower()).Deprecated = $false
                }
                if ($builtinPolicySetDefinition.Properties.metadata.preview -eq $true -or $builtinPolicySetDefinition.Properties.displayname -like "``[*Preview``]*") {
                    $script:htCacheDefinitionsPolicySet.(($builtinPolicySetDefinition.Id).ToLower()).Preview = $builtinPolicySetDefinition.Properties.metadata.preview
                }
                else {
                    $script:htCacheDefinitionsPolicySet.(($builtinPolicySetDefinition.Id).ToLower()).Preview = $false
                }
                $script:htCacheDefinitionsPolicySet.(($builtinPolicySetDefinition.Id).ToLower()).Json = $builtinPolicySetDefinition
            }
        }

        if ($builtInCapability -eq 'RoleDefinitions') {

            $roledefinitionsAPIVersion = $azAPICallConf['htParameters'].APIMappingCloudEnvironment.roledefinitions.($azAPICallConf['htParameters'].azureCloudEnvironment)

            #region subscriptionScope
            if ($ignoreARMLocation) {
                $currentTask = 'Caching built-in Role definitions (subscriptionScope)'
                Write-Host " $currentTask"
                $uri = "$($azAPICallConf['azAPIEndpointUrls'].'ARM')/subscriptions/$($azAPICallConf['checkContext'].Subscription.Id)/providers/Microsoft.Authorization/roleDefinitions?api-version=$($roledefinitionsAPIVersion)&`$filter=type eq 'BuiltInRole'"
            }
            else {
                $currentTask = "Caching built-in Role definitions (Location: '$($ARMLocation)') (subscriptionScope)"
                Write-Host " $currentTask"
                $uri = "$($azAPICallConf['azAPIEndpointUrls']."ARM$($ARMLocation)")/subscriptions/$($azAPICallConf['checkContext'].Subscription.Id)/providers/Microsoft.Authorization/roleDefinitions?api-version=$($roledefinitionsAPIVersion)&`$filter=type eq 'BuiltInRole'"
            }

            $method = 'GET'
            $requestRoleDefinitionAPI = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask

            Write-Host " $($requestRoleDefinitionAPI.Count) built-in Role definitions returned (subscriptionScope)"
            foreach ($roleDefinition in $requestRoleDefinitionAPI) {
                if (
                    (
                        $roleDefinition.properties.permissions.actions -contains 'Microsoft.Authorization/roleassignments/write' -or
                        $roleDefinition.properties.permissions.actions -contains 'Microsoft.Authorization/roleassignments/*' -or
                        $roleDefinition.properties.permissions.actions -contains 'Microsoft.Authorization/*/write' -or
                        $roleDefinition.properties.permissions.actions -contains 'Microsoft.Authorization/*' -or
                        $roleDefinition.properties.permissions.actions -contains '*/write' -or
                        $roleDefinition.properties.permissions.actions -contains '*'
                    ) -and (
                        $roleDefinition.properties.permissions.notActions -notcontains 'Microsoft.Authorization/roleassignments/write' -and
                        $roleDefinition.properties.permissions.notActions -notcontains 'Microsoft.Authorization/roleassignments/*' -and
                        $roleDefinition.properties.permissions.notActions -notcontains 'Microsoft.Authorization/*/write' -and
                        $roleDefinition.properties.permissions.notActions -notcontains 'Microsoft.Authorization/*' -and
                        $roleDefinition.properties.permissions.notActions -notcontains '*/write' -and
                        $roleDefinition.properties.permissions.notActions -notcontains '*'
                    )
                ) {
                    $roleCapable4RoleAssignmentsWrite = $true
                }
                else {
                    $roleCapable4RoleAssignmentsWrite = $false
                }

                ($script:htCacheDefinitionsRole).($roleDefinition.name) = @{
                    Id                       = ($roleDefinition.name)
                    Name                     = ($roleDefinition.properties.roleName)
                    IsCustom                 = $false
                    AssignableScopes         = ($roleDefinition.properties.assignableScopes)
                    Actions                  = ($roleDefinition.properties.permissions.actions)
                    NotActions               = ($roleDefinition.properties.permissions.notActions)
                    DataActions              = ($roleDefinition.properties.permissions.dataActions)
                    NotDataActions           = ($roleDefinition.properties.permissions.notDataActions)
                    Json                     = $roleDefinition
                    LinkToAzAdvertizer       = "<a class=`"externallink`" href=`"https://www.azadvertizer.net/azrolesadvertizer/$($roleDefinition.name).html`" target=`"_blank`" rel=`"noopener`">$($roleDefinition.properties.roleName)</a>"
                    RoleCanDoRoleAssignments = $roleCapable4RoleAssignmentsWrite
                }

            }
            #endregion subscriptionScope

            #region tenantScope
            if ($ignoreARMLocation) {
                $currentTask = 'Caching built-in Role definitions (tenantScope)'
                Write-Host " $currentTask"
                $uri = "$($azAPICallConf['azAPIEndpointUrls'].'ARM')/providers/Microsoft.Authorization/roleDefinitions?api-version=$($roledefinitionsAPIVersion)&`$filter=type eq 'BuiltInRole'"
            }
            else {
                $currentTask = "Caching built-in Role definitions (Location: '$($ARMLocation)') (tenantScope)"
                Write-Host " $currentTask"
                $uri = "$($azAPICallConf['azAPIEndpointUrls']."ARM$($ARMLocation)")/providers/Microsoft.Authorization/roleDefinitions?api-version=$($roledefinitionsAPIVersion)&`$filter=type eq 'BuiltInRole'"
            }

            $method = 'GET'
            $requestRoleDefinitionTenantScopeAPI = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask

            Write-Host " $($requestRoleDefinitionTenantScopeAPI.Count) built-in Role definitions returned (tenantScope)"
            foreach ($roleDefinition in $requestRoleDefinitionTenantScopeAPI) {
                if (-not $htCacheDefinitionsRole.($roleDefinition.name)) {
                    Write-Host "tenantScope role: '$($roleDefinition.properties.roleName)' - $($roleDefinition.name)"
                    if (
                        (
                            $roleDefinition.properties.permissions.actions -contains 'Microsoft.Authorization/roleassignments/write' -or
                            $roleDefinition.properties.permissions.actions -contains 'Microsoft.Authorization/roleassignments/*' -or
                            $roleDefinition.properties.permissions.actions -contains 'Microsoft.Authorization/*/write' -or
                            $roleDefinition.properties.permissions.actions -contains 'Microsoft.Authorization/*' -or
                            $roleDefinition.properties.permissions.actions -contains '*/write' -or
                            $roleDefinition.properties.permissions.actions -contains '*'
                        ) -and (
                            $roleDefinition.properties.permissions.notActions -notcontains 'Microsoft.Authorization/roleassignments/write' -and
                            $roleDefinition.properties.permissions.notActions -notcontains 'Microsoft.Authorization/roleassignments/*' -and
                            $roleDefinition.properties.permissions.notActions -notcontains 'Microsoft.Authorization/*/write' -and
                            $roleDefinition.properties.permissions.notActions -notcontains 'Microsoft.Authorization/*' -and
                            $roleDefinition.properties.permissions.notActions -notcontains '*/write' -and
                            $roleDefinition.properties.permissions.notActions -notcontains '*'
                        )
                    ) {
                        $roleCapable4RoleAssignmentsWrite = $true
                    }
                    else {
                        $roleCapable4RoleAssignmentsWrite = $false
                    }

                    ($script:htCacheDefinitionsRole).($roleDefinition.name) = @{
                        Id                       = ($roleDefinition.name)
                        Name                     = ($roleDefinition.properties.roleName)
                        IsCustom                 = $false
                        AssignableScopes         = ($roleDefinition.properties.assignableScopes)
                        Actions                  = ($roleDefinition.properties.permissions.actions)
                        NotActions               = ($roleDefinition.properties.permissions.notActions)
                        DataActions              = ($roleDefinition.properties.permissions.dataActions)
                        NotDataActions           = ($roleDefinition.properties.permissions.notDataActions)
                        Json                     = $roleDefinition
                        LinkToAzAdvertizer       = "<a class=`"externallink`" href=`"https://www.azadvertizer.net/azrolesadvertizer/$($roleDefinition.name).html`" target=`"_blank`" rel=`"noopener`">$($roleDefinition.properties.roleName)</a>"
                        RoleCanDoRoleAssignments = $roleCapable4RoleAssignmentsWrite
                    }
                }

            }
            #endregion tenantScope
        }
    }

    $script:builtInPolicyDefinitionsCount = $htCacheDefinitionsPolicy.Values.where({ $_.Type -eq 'BuiltIn' }).count

    $endDefinitionsCaching = Get-Date
    Write-Host "Caching built-in definitions duration: $((New-TimeSpan -Start $startDefinitionsCaching -End $endDefinitionsCaching).TotalSeconds) seconds"
}