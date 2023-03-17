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
        $htRoleDefinitionIdsUsedInPolicy = $using:htRoleDefinitionIdsUsedInPolicy
        $ValidPolicyEffects = $using:ValidPolicyEffects
        $htHashesBuiltInPolicy = $using:htHashesBuiltInPolicy
        #functions
        $function:detectPolicyEffect = $using:funcDetectPolicyEffect
        $function:getPolicyHash = $using:funcGetPolicyHash

        if ($builtInCapability -eq 'PolicyDefinitions') {
            $currentTask = 'Caching built-in Policy definitions'
            #Write-Host " $currentTask"
            $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/providers/Microsoft.Authorization/policyDefinitions?api-version=2021-06-01&`$filter=policyType eq 'BuiltIn'"
            $method = 'GET'
            $requestPolicyDefinitionAPI = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask

            Write-Host " $($requestPolicyDefinitionAPI.Count) built-in Policy definitions returned"
            $builtinPolicyDefinitions = $requestPolicyDefinitionAPI.where( { $_.properties.policyType -eq 'BuiltIn' } )

            foreach ($builtinPolicyDefinition in $builtinPolicyDefinitions) {
                $script:htCacheDefinitionsPolicy.(($builtinPolicyDefinition.Id).ToLower()) = @{}
                $script:htCacheDefinitionsPolicy.(($builtinPolicyDefinition.Id).ToLower()).Id = ($builtinPolicyDefinition.Id).ToLower()
                $script:htCacheDefinitionsPolicy.(($builtinPolicyDefinition.Id).ToLower()).ScopeMGLevel = ''
                $script:htCacheDefinitionsPolicy.(($builtinPolicyDefinition.Id).ToLower()).Scope = 'n/a'
                $script:htCacheDefinitionsPolicy.(($builtinPolicyDefinition.Id).ToLower()).ScopeMgSub = 'n/a'
                $script:htCacheDefinitionsPolicy.(($builtinPolicyDefinition.Id).ToLower()).ScopeId = 'n/a'
                $script:htCacheDefinitionsPolicy.(($builtinPolicyDefinition.Id).ToLower()).DisplayName = $builtinPolicyDefinition.Properties.displayname
                $script:htCacheDefinitionsPolicy.(($builtinPolicyDefinition.Id).ToLower()).Name = $builtinPolicyDefinition.Name
                $script:htCacheDefinitionsPolicy.(($builtinPolicyDefinition.Id).ToLower()).Description = $builtinPolicyDefinition.Properties.description
                $script:htCacheDefinitionsPolicy.(($builtinPolicyDefinition.Id).ToLower()).Type = $builtinPolicyDefinition.Properties.policyType
                $script:htCacheDefinitionsPolicy.(($builtinPolicyDefinition.Id).ToLower()).Category = $builtinPolicyDefinition.Properties.metadata.category
                $script:htCacheDefinitionsPolicy.(($builtinPolicyDefinition.Id).ToLower()).Version = $builtinPolicyDefinition.Properties.metadata.version
                $script:htCacheDefinitionsPolicy.(($builtinPolicyDefinition.Id).ToLower()).PolicyDefinitionId = ($builtinPolicyDefinition.Id).ToLower()
                $script:htCacheDefinitionsPolicy.(($builtinPolicyDefinition.Id).ToLower()).LinkToAzAdvertizer = "<a class=`"externallink`" href=`"https://www.azadvertizer.net/azpolicyadvertizer/$(($builtinPolicyDefinition.Id -replace '.*/')).html`" target=`"_blank`" rel=`"noopener`">$($builtinPolicyDefinition.Properties.displayname)</a>"
                $script:htCacheDefinitionsPolicy.(($builtinPolicyDefinition.Id).ToLower()).ALZ = $false
                $script:htCacheDefinitionsPolicy.(($builtinPolicyDefinition.Id).ToLower()).ALZState = ''
                $script:htCacheDefinitionsPolicy.(($builtinPolicyDefinition.Id).ToLower()).ALZLatestVer = ''
                $script:htCacheDefinitionsPolicy.(($builtinPolicyDefinition.Id).ToLower()).ALZIdentificationLevel = ''
                $script:htCacheDefinitionsPolicy.(($builtinPolicyDefinition.Id).ToLower()).ALZPolicyName = ''
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
                    foreach ($roledefinitionId in $builtinPolicyDefinition.properties.policyRule.then.details.roleDefinitionIds) {
                        if (-not $htRoleDefinitionIdsUsedInPolicy.($roledefinitionId)) {
                            $script:htRoleDefinitionIdsUsedInPolicy.($roledefinitionId) = @{}
                            $script:htRoleDefinitionIdsUsedInPolicy.($roledefinitionId).UsedInPolicies = [array]$builtinPolicyDefinition.Id
                        }
                        else {
                            $usedInPolicies = $htRoleDefinitionIdsUsedInPolicy.($roledefinitionId).UsedInPolicies
                            $usedInPolicies += $builtinPolicyDefinition.Id
                            $script:htRoleDefinitionIdsUsedInPolicy.($roledefinitionId).UsedInPolicies = $usedInPolicies
                        }
                    }
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
            #Write-Host " $currentTask"
            $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/providers/Microsoft.Authorization/policyDefinitions?api-version=2021-06-01&`$filter=policyType eq 'Static'"
            $method = 'GET'
            $requestPolicyDefinitionAPI = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask

            Write-Host " $($requestPolicyDefinitionAPI.Count) static Policy definitions returned"
            $staticPolicyDefinitions = $requestPolicyDefinitionAPI.where( { $_.properties.policyType -eq 'Static' } )

            foreach ($staticPolicyDefinition in $staticPolicyDefinitions) {
                $script:htCacheDefinitionsPolicy.(($staticPolicyDefinition.Id).ToLower()) = @{}
                $script:htCacheDefinitionsPolicy.(($staticPolicyDefinition.Id).ToLower()).Id = ($staticPolicyDefinition.Id).ToLower()
                $script:htCacheDefinitionsPolicy.(($staticPolicyDefinition.Id).ToLower()).ScopeMGLevel = ''
                $script:htCacheDefinitionsPolicy.(($staticPolicyDefinition.Id).ToLower()).Scope = 'n/a'
                $script:htCacheDefinitionsPolicy.(($staticPolicyDefinition.Id).ToLower()).ScopeMgSub = 'n/a'
                $script:htCacheDefinitionsPolicy.(($staticPolicyDefinition.Id).ToLower()).ScopeId = 'n/a'
                $script:htCacheDefinitionsPolicy.(($staticPolicyDefinition.Id).ToLower()).DisplayName = $staticPolicyDefinition.Properties.displayname
                $script:htCacheDefinitionsPolicy.(($staticPolicyDefinition.Id).ToLower()).Name = $staticPolicyDefinition.Name
                $script:htCacheDefinitionsPolicy.(($staticPolicyDefinition.Id).ToLower()).Description = $staticPolicyDefinition.Properties.description
                $script:htCacheDefinitionsPolicy.(($staticPolicyDefinition.Id).ToLower()).Type = $staticPolicyDefinition.Properties.policyType
                $script:htCacheDefinitionsPolicy.(($staticPolicyDefinition.Id).ToLower()).Category = $staticPolicyDefinition.Properties.metadata.category
                $script:htCacheDefinitionsPolicy.(($staticPolicyDefinition.Id).ToLower()).Version = $staticPolicyDefinition.Properties.metadata.version
                $script:htCacheDefinitionsPolicy.(($staticPolicyDefinition.Id).ToLower()).PolicyDefinitionId = ($staticPolicyDefinition.Id).ToLower()
                $script:htCacheDefinitionsPolicy.(($staticPolicyDefinition.Id).ToLower()).LinkToAzAdvertizer = "<a class=`"externallink`" href=`"https://www.azadvertizer.net/azpolicyadvertizer/$(($staticPolicyDefinition.Id -replace '.*/')).html`" target=`"_blank`" rel=`"noopener`">$($staticPolicyDefinition.Properties.displayname)</a>"
                $script:htCacheDefinitionsPolicy.(($staticPolicyDefinition.Id).ToLower()).ALZ = $false
                $script:htCacheDefinitionsPolicy.(($staticPolicyDefinition.Id).ToLower()).ALZState = ''
                $script:htCacheDefinitionsPolicy.(($staticPolicyDefinition.Id).ToLower()).ALZLatestVer = ''
                $script:htCacheDefinitionsPolicy.(($staticPolicyDefinition.Id).ToLower()).ALZIdentificationLevel = ''
                $script:htCacheDefinitionsPolicy.(($staticPolicyDefinition.Id).ToLower()).ALZPolicyName = ''

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
                    foreach ($roledefinitionId in $staticPolicyDefinition.properties.policyRule.then.details.roleDefinitionIds) {
                        if (-not $htRoleDefinitionIdsUsedInPolicy.($roledefinitionId)) {
                            $script:htRoleDefinitionIdsUsedInPolicy.($roledefinitionId) = @{}
                            $script:htRoleDefinitionIdsUsedInPolicy.($roledefinitionId).UsedInPolicies = [array]$staticPolicyDefinition.Id
                        }
                        else {
                            $usedInPolicies = $htRoleDefinitionIdsUsedInPolicy.($roledefinitionId).UsedInPolicies
                            $usedInPolicies += $staticPolicyDefinition.Id
                            $script:htRoleDefinitionIdsUsedInPolicy.($roledefinitionId).UsedInPolicies = $usedInPolicies
                        }
                    }
                }
                else {
                    $script:htCacheDefinitionsPolicy.(($staticPolicyDefinition.Id).ToLower()).RoleDefinitionIds = 'n/a'
                }
            }
        }

        if ($builtInCapability -eq 'PolicySetDefinitions') {

            $currentTask = 'Caching built-in PolicySet definitions'
            #Write-Host " $currentTask"
            $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/providers/Microsoft.Authorization/policySetDefinitions?api-version=2021-06-01&`$filter=policyType eq 'BuiltIn'"
            $method = 'GET'
            $requestPolicySetDefinitionAPI = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask

            $builtinPolicySetDefinitions = $requestPolicySetDefinitionAPI.where( { $_.properties.policyType -eq 'BuiltIn' } )
            Write-Host " $($requestPolicySetDefinitionAPI.Count) built-in PolicySet definitions returned"
            foreach ($builtinPolicySetDefinition in $builtinPolicySetDefinitions) {
                $script:htCacheDefinitionsPolicySet.(($builtinPolicySetDefinition.Id).ToLower()) = @{}
                $script:htCacheDefinitionsPolicySet.(($builtinPolicySetDefinition.Id).ToLower()).Id = ($builtinPolicySetDefinition.Id).ToLower()
                $script:htCacheDefinitionsPolicySet.(($builtinPolicySetDefinition.Id).ToLower()).ScopeMGLevel = ''
                $script:htCacheDefinitionsPolicySet.(($builtinPolicySetDefinition.Id).ToLower()).Scope = 'n/a'
                $script:htCacheDefinitionsPolicySet.(($builtinPolicySetDefinition.Id).ToLower()).ScopeMgSub = 'n/a'
                $script:htCacheDefinitionsPolicySet.(($builtinPolicySetDefinition.Id).ToLower()).ScopeId = 'n/a'
                $script:htCacheDefinitionsPolicySet.(($builtinPolicySetDefinition.Id).ToLower()).DisplayName = $builtinPolicySetDefinition.Properties.displayname
                $script:htCacheDefinitionsPolicySet.(($builtinPolicySetDefinition.Id).ToLower()).Name = $builtinPolicySetDefinition.Name
                $script:htCacheDefinitionsPolicySet.(($builtinPolicySetDefinition.Id).ToLower()).Description = $builtinPolicySetDefinition.Properties.description
                $script:htCacheDefinitionsPolicySet.(($builtinPolicySetDefinition.Id).ToLower()).Type = $builtinPolicySetDefinition.Properties.policyType
                $script:htCacheDefinitionsPolicySet.(($builtinPolicySetDefinition.Id).ToLower()).Category = $builtinPolicySetDefinition.Properties.metadata.category
                $script:htCacheDefinitionsPolicySet.(($builtinPolicySetDefinition.Id).ToLower()).Version = $builtinPolicySetDefinition.Properties.metadata.version
                $script:htCacheDefinitionsPolicySet.(($builtinPolicySetDefinition.Id).ToLower()).PolicyDefinitionId = ($builtinPolicySetDefinition.Id).ToLower()
                $script:htCacheDefinitionsPolicySet.(($builtinPolicySetDefinition.Id).ToLower()).LinkToAzAdvertizer = "<a class=`"externallink`" href=`"https://www.azadvertizer.net/azpolicyinitiativesadvertizer/$(($builtinPolicySetDefinition.Id -replace '.*/')).html`" target=`"_blank`" rel=`"noopener`">$($builtinPolicySetDefinition.Properties.displayname)</a>"
                $script:htCacheDefinitionsPolicySet.(($builtinPolicySetDefinition.Id).ToLower()).ALZ = $false
                $script:htCacheDefinitionsPolicySet.(($builtinPolicySetDefinition.Id).ToLower()).ALZState = ''
                $script:htCacheDefinitionsPolicySet.(($builtinPolicySetDefinition.Id).ToLower()).ALZLatestVer = ''
                $script:htCacheDefinitionsPolicySet.(($builtinPolicySetDefinition.Id).ToLower()).ALZIdentificationLevel = ''
                $script:htCacheDefinitionsPolicySet.(($builtinPolicySetDefinition.Id).ToLower()).ALZPolicySetName = ''
                $arrayPolicySetPolicyIdsToLower = @()
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
            $currentTask = 'Caching built-in Role definitions'
            #Write-Host " $currentTask"
            $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($azAPICallConf['checkContext'].Subscription.Id)/providers/Microsoft.Authorization/roleDefinitions?api-version=2018-07-01&`$filter=type eq 'BuiltInRole'"
            $method = 'GET'
            $requestRoleDefinitionAPI = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask

            Write-Host " $($requestRoleDefinitionAPI.Count) built-in Role definitions returned"
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

                    ($script:htCacheDefinitionsRole).($roleDefinition.name) = @{}
                    ($script:htCacheDefinitionsRole).($roleDefinition.name).Id = ($roleDefinition.name)
                    ($script:htCacheDefinitionsRole).($roleDefinition.name).Name = ($roleDefinition.properties.roleName)
                    ($script:htCacheDefinitionsRole).($roleDefinition.name).IsCustom = $false
                    ($script:htCacheDefinitionsRole).($roleDefinition.name).AssignableScopes = ($roleDefinition.properties.assignableScopes)
                    ($script:htCacheDefinitionsRole).($roleDefinition.name).Actions = ($roleDefinition.properties.permissions.actions)
                    ($script:htCacheDefinitionsRole).($roleDefinition.name).NotActions = ($roleDefinition.properties.permissions.notActions)
                    ($script:htCacheDefinitionsRole).($roleDefinition.name).DataActions = ($roleDefinition.properties.permissions.dataActions)
                    ($script:htCacheDefinitionsRole).($roleDefinition.name).NotDataActions = ($roleDefinition.properties.permissions.notDataActions)
                    ($script:htCacheDefinitionsRole).($roleDefinition.name).Json = ($roleDefinition.properties)
                    ($script:htCacheDefinitionsRole).($roleDefinition.name).LinkToAzAdvertizer = "<a class=`"externallink`" href=`"https://www.azadvertizer.net/azrolesadvertizer/$($roleDefinition.name).html`" target=`"_blank`" rel=`"noopener`">$($roleDefinition.properties.roleName)</a>"
                    ($script:htCacheDefinitionsRole).($roleDefinition.name).RoleCanDoRoleAssignments = $roleCapable4RoleAssignmentsWrite
            }
        }
    }

    $script:builtInPolicyDefinitionsCount = $htCacheDefinitionsPolicy.Values.where({ $_.Type -eq 'BuiltIn' }).count

    $endDefinitionsCaching = Get-Date
    Write-Host "Caching built-in definitions duration: $((New-TimeSpan -Start $startDefinitionsCaching -End $endDefinitionsCaching).TotalSeconds) seconds"
}