function processDataCollection {
    [CmdletBinding()]Param(
        [string]$mgId
    )

    Write-Host ' CustomDataCollection ManagementGroups'
    $startMgLoop = Get-Date

    $allManagementGroupsFromEntitiesChildOfRequestedMg = $arrayEntitiesFromAPI.where( { $_.type -eq 'Microsoft.Management/managementGroups' -and ($_.Name -eq $mgId -or $_.properties.parentNameChain -contains $mgId) })
    $allManagementGroupsFromEntitiesChildOfRequestedMgCount = ($allManagementGroupsFromEntitiesChildOfRequestedMg).Count
    Write-Host " $allManagementGroupsFromEntitiesChildOfRequestedMgCount Management Groups: $(($allManagementGroupsFromEntitiesChildOfRequestedMg.Name | Sort-Object) -join ', ')"
    
    $mgBatch = ($allManagementGroupsFromEntitiesChildOfRequestedMg | Group-Object -Property { ($_.properties.parentNameChain).Count }) | Sort-Object -Property Name
    foreach ($batchLevel in $mgBatch) {
        Write-Host "  Processing Management Groups L$($batchLevel.Name) ($($batchLevel.Count) Management Groups)"

        showMemoryUsage

        $batchLevel.Group | ForEach-Object -Parallel {
            $mgdetail = $_
            #region UsingVARs
            #Parameters MG&Sub related
            $CsvDelimiter = $using:CsvDelimiter
            $CsvDelimiterOpposite = $using:CsvDelimiterOpposite
            $ManagementGroupId = $using:ManagementGroupId
            #fromOtherFunctions
            $azAPICallConf = $using:azAPICallConf
            $scriptPath = $using:ScriptPath
            #Array&HTs
            $newTable = $using:newTable
            $customDataCollectionDuration = $using:customDataCollectionDuration
            $htSubscriptionTagList = $using:htSubscriptionTagList
            $htResourceTypesUniqueResource = $using:htResourceTypesUniqueResource
            $htAllTagList = $using:htAllTagList
            $htSubscriptionTags = $using:htSubscriptionTags
            $htCacheDefinitionsPolicy = $using:htCacheDefinitionsPolicy
            $htCacheDefinitionsPolicySet = $using:htCacheDefinitionsPolicySet
            $htCacheDefinitionsRole = $using:htCacheDefinitionsRole
            $htCacheDefinitionsBlueprint = $using:htCacheDefinitionsBlueprint
            $htRoleDefinitionIdsUsedInPolicy = $using:htRoleDefinitionIdsUsedInPolicy
            $htCachePolicyComplianceMG = $using:htCachePolicyComplianceMG
            $htCachePolicyComplianceResponseTooLargeMG = $using:htCachePolicyComplianceResponseTooLargeMG
            $htCacheAssignmentsRole = $using:htCacheAssignmentsRole
            $htCacheAssignmentsRBACOnResourceGroupsAndResources = $using:htCacheAssignmentsRBACOnResourceGroupsAndResources
            $htCacheAssignmentsBlueprint = $using:htCacheAssignmentsBlueprint
            $htCacheAssignmentsPolicy = $using:htCacheAssignmentsPolicy
            $htPolicyAssignmentExemptions = $using:htPolicyAssignmentExemptions
            $htManagementGroupsMgPath = $using:htManagementGroupsMgPath
            $LimitPOLICYPolicyDefinitionsScopedManagementGroup = $using:LimitPOLICYPolicyDefinitionsScopedManagementGroup
            $LimitPOLICYPolicySetDefinitionsScopedManagementGroup = $using:LimitPOLICYPolicySetDefinitionsScopedManagementGroup
            $LimitPOLICYPolicyAssignmentsManagementGroup = $using:LimitPOLICYPolicyAssignmentsManagementGroup
            $LimitPOLICYPolicySetAssignmentsManagementGroup = $using:LimitPOLICYPolicySetAssignmentsManagementGroup
            $LimitRBACRoleAssignmentsManagementGroup = $using:LimitRBACRoleAssignmentsManagementGroup
            $arrayEntitiesFromAPI = $using:arrayEntitiesFromAPI
            $allManagementGroupsFromEntitiesChildOfRequestedMgCount = $using:allManagementGroupsFromEntitiesChildOfRequestedMgCount
            $arrayDataCollectionProgressMg = $using:arrayDataCollectionProgressMg
            $arrayDiagnosticSettingsMgSub = $using:arrayDiagnosticSettingsMgSub
            $htMgAtScopePolicyAssignments = $using:htMgAtScopePolicyAssignments
            $htMgAtScopePoliciesScoped = $using:htMgAtScopePoliciesScoped
            $htMgAtScopeRoleAssignments = $using:htMgAtScopeRoleAssignments
            $htMgASCSecureScore = $using:htMgASCSecureScore
            $htRoleAssignmentsFromAPIInheritancePrevention = $using:htRoleAssignmentsFromAPIInheritancePrevention
            $htNamingValidation = $using:htNamingValidation
            $htPrincipals = $using:htPrincipals
            $htServicePrincipals = $using:htServicePrincipals
            $htUserTypesGuest = $using:htUserTypesGuest
            #other
            $function:addRowToTable = $using:funcAddRowToTable
            $function:namingValidation = $using:funcNamingValidation
            $function:resolveObjectIds = $using:funcResolveObjectIds

            #$function:dataCollectionFunctions = $using:funcdataCollectionFunctions

            $function:dataCollectionMGSecureScore = $using:funcDataCollectionMGSecureScore
            $function:dataCollectionDiagnosticsMG = $using:funcDataCollectionDiagnosticsMG
            $function:dataCollectionPolicyComplianceStates = $using:funcDataCollectionPolicyComplianceStates
            $function:dataCollectionBluePrintDefinitionsMG = $using:funcDataCollectionBluePrintDefinitionsMG
            $function:dataCollectionPolicyExemptions = $using:funcDataCollectionPolicyExemptions
            $function:dataCollectionPolicyDefinitions = $using:funcDataCollectionPolicyDefinitions
            $function:dataCollectionPolicySetDefinitions = $using:funcDataCollectionPolicySetDefinitions
            $function:dataCollectionPolicyAssignmentsMG = $using:funcDataCollectionPolicyAssignmentsMG
            $function:dataCollectionRoleDefinitions = $using:funcDataCollectionRoleDefinitions
            $function:dataCollectionRoleAssignmentsMG = $using:funcDataCollectionRoleAssignmentsMG

            #endregion usingVARS
            $builtInPolicyDefinitionsCount = $using:builtInPolicyDefinitionsCount

            $addRowToTableDone = $false

            $MgDetailThis = $htManagementGroupsMgPath.($mgdetail.Name)
            $MgParentId = $MgDetailThis.Parent
            $hierarchyLevel = $MgDetailThis.ParentNameChainCount

            if ($MgParentId -eq '__TenantRoot__') {
                $MgParentId = 'TenantRoot'
                $MgParentName = $MgParentId
            }
            else {
                $MgParentName = $htManagementGroupsMgPath.($MgParentId).DisplayName
            }

            $rndom = Get-Random -Minimum 10 -Maximum 750
            start-sleep -Millisecond $rndom
            $startMgLoopThis = Get-Date

            if ($azAPICallConf['htParameters'].HierarchyMapOnly -eq $false) {

                #namingValidation
                if (-not [string]::IsNullOrEmpty($mgdetail.properties.displayName)) {
                    $namingValidationResult = NamingValidation -toCheck $mgdetail.properties.displayName
                    if ($namingValidationResult.Count -gt 0) {
                        $script:htNamingValidation.ManagementGroup.($mgdetail.Name) = @{}
                        $script:htNamingValidation.ManagementGroup.($mgdetail.Name).nameInvalidChars = ($namingValidationResult -join '')
                        $script:htNamingValidation.ManagementGroup.($mgdetail.Name).name = $mgdetail.properties.displayName
                    }
                }

                $targetMgOrSub = 'MG'
                $baseParameters = @{
                    scopeId          = $mgdetail.Name
                    scopeDisplayName = $mgdetail.properties.displayName
                }

                #ManagementGroupASCSecureScore
                $mgAscSecureScoreResult = DataCollectionMGSecureScore -Id $mgdetail.Name

                $addRowToTableParameters = @{
                    hierarchyLevel         = $hierarchyLevel
                    mgParentId             = $mgParentId
                    mgParentName           = $mgParentName
                    mgAscSecureScoreResult = $mgAscSecureScoreResult
                }

                #mg diag
                DataCollectionDiagnosticsMG @baseParameters

                if ($azAPICallConf['htParameters'].NoPolicyComplianceStates -eq $false) {
                    #MGPolicyCompliance
                    DataCollectionPolicyComplianceStates @baseParameters -TargetMgOrSub $targetMgOrSub
                }

                #MGBlueprintDefinitions
                $functionReturn = DataCollectionBluePrintDefinitionsMG @baseParameters @addRowToTableParameters
                if ($functionReturn.'addRowToTableDone') {
                    $addRowToTableDone = $true
                }

                #MGPolicyExemptions
                DataCollectionPolicyExemptions @baseParameters -TargetMgOrSub $targetMgOrSub

                #MGPolicyDefinitions
                $functionReturn = DataCollectionPolicyDefinitions @baseParameters -TargetMgOrSub $targetMgOrSub
                $policyDefinitionsScopedCount = $functionReturn.'PolicyDefinitionsScopedCount'

                #MGPolicySetDefinitions
                $functionReturn = DataCollectionPolicySetDefinitions @baseParameters -TargetMgOrSub $targetMgOrSub
                $policySetDefinitionsScopedCount = $functionReturn.'PolicySetDefinitionsScopedCount'

                if (-not $htMgAtScopePoliciesScoped.($mgdetail.Name)) {
                    $script:htMgAtScopePoliciesScoped.($mgdetail.Name) = @{}
                    $script:htMgAtScopePoliciesScoped.($mgdetail.Name).ScopedCount = $policyDefinitionsScopedCount + $policySetDefinitionsScopedCount
                }

                $scopedPolicyCounts = @{
                    policyDefinitionsScopedCount    = $policyDefinitionsScopedCount
                    policySetDefinitionsScopedCount = $policySetDefinitionsScopedCount
                }

                #MgPolicyAssignments
                $functionReturn = DataCollectionPolicyAssignmentsMG @baseParameters @addRowToTableParameters @scopedPolicyCounts
                if ($functionReturn.'addRowToTableDone') {
                    $addRowToTableDone = $true
                }

                #MGRoleDefinitions
                DataCollectionRoleDefinitions @baseParameters -TargetMgOrSub $targetMgOrSub

                #MGRoleAssignments
                $functionReturn = DataCollectionRoleAssignmentsMG @baseParameters @addRowToTableParameters
                if ($functionReturn.'addRowToTableDone') {
                    $addRowToTableDone = $true
                }

                if ($addRowToTableDone -ne $true) {
                    addRowToTable `
                        -level $hierarchyLevel `
                        -mgName $mgdetail.properties.displayName `
                        -mgId $mgdetail.Name `
                        -mgParentId $mgParentId `
                        -mgParentName $mgParentName `
                        -mgASCSecureScore $mgAscSecureScoreResult
                }
            }
            else {
                addRowToTable `
                    -level $hierarchyLevel `
                    -mgName $mgdetail.properties.displayName `
                    -mgId $mgdetail.Name `
                    -mgParentId $mgParentId `
                    -mgParentName $mgParentName `
                    -mgASCSecureScore $mgAscSecureScoreResult
            }


            $endMgLoopThis = Get-Date
            $null = $script:customDataCollectionDuration.Add([PSCustomObject]@{
                    Type        = 'Mg'
                    Id          = $mgdetail.Name
                    DurationSec = (NEW-TIMESPAN -Start $startMgLoopThis -End $endMgLoopThis).TotalSeconds
                })

            $null = $script:arrayDataCollectionProgressMg.Add($mgdetail.Name)
            $progressCount = ($arrayDataCollectionProgressMg).Count
            Write-Host "  $($progressCount)/$($allManagementGroupsFromEntitiesChildOfRequestedMgCount) Management Groups processed"

        } -ThrottleLimit $ThrottleLimit
        #[System.GC]::Collect()
    }

    $endMgLoop = Get-Date
    Write-Host " CustomDataCollection ManagementGroups processing duration: $((NEW-TIMESPAN -Start $startMgLoop -End $endMgLoop).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startMgLoop -End $endMgLoop).TotalSeconds) seconds)"

    apiCallTracking -stage 'CustomDataCollection ManagementGroups' -spacing ' '

    #test
    if ($builtInPolicyDefinitionsCount -ne ($($htCacheDefinitionsPolicy).Values.where({ $_.Type -eq 'BuiltIn' }).Count) -or $builtInPolicyDefinitionsCount -ne ((($htCacheDefinitionsPolicy).Values.where( { $_.Type -eq 'BuiltIn' } )).Count)) {
        Write-Host "$builtInPolicyDefinitionsCount -ne $($($htCacheDefinitionsPolicy).Values.where({$_.Type -eq 'BuiltIn'}).Count) OR $builtInPolicyDefinitionsCount -ne $((($htCacheDefinitionsPolicy).Values.where( {$_.Type -eq 'BuiltIn'} )).Count)"
        Write-Host 'Listing all PolicyDefinitions:'
        foreach ($tmpPolicyDefinitionId in ($($htCacheDefinitionsPolicy).Keys | Sort-Object)) {
            Write-Host $tmpPolicyDefinitionId
        }
    }


    #region SUBSCRIPTION
    Write-Host ' CustomDataCollection Subscriptions'
    $subsExcludedStateCount = ($outOfScopeSubscriptions.where( { $_.outOfScopeReason -like 'State*' } )).Count
    $subsExcludedWhitelistCount = ($outOfScopeSubscriptions.where( { $_.outOfScopeReason -like 'QuotaId*' } )).Count
    if ($subsExcludedStateCount -gt 0) {
        Write-Host "  CustomDataCollection $($subsExcludedStateCount) Subscriptions excluded (State != enabled)"
    }
    if ($subsExcludedWhitelistCount -gt 0) {
        Write-Host "  CustomDataCollection $($subsExcludedWhitelistCount) Subscriptions excluded (not in quotaId whitelist: '$($SubscriptionQuotaIdWhitelist -join ', ')' OR is AAD_ quotaId)"
    }
    Write-Host " CustomDataCollection Subscriptions will process $subsToProcessInCustomDataCollectionCount of $childrenSubscriptionsCount"

    $startSubLoop = Get-Date
    if ($subsToProcessInCustomDataCollectionCount -gt 0) {

        $counterBatch = [PSCustomObject] @{ Value = 0 }
        $batchSize = 100
        if ($subsToProcessInCustomDataCollectionCount -gt 500) {
            $batchSize = 200
        }
        Write-Host " Subscriptions Batch size: $batchSize"

        $subscriptionsBatch = $subsToProcessInCustomDataCollection | Group-Object -Property { [math]::Floor($counterBatch.Value++ / $batchSize) }
        $batchCnt = 0
        foreach ($batch in $subscriptionsBatch) {
            #[System.GC]::Collect()
            $startBatch = Get-Date
            $batchCnt++
            Write-Host " processing Batch #$batchCnt/$(($subscriptionsBatch | Measure-Object).Count) ($(($batch.Group | Measure-Object).Count) Subscriptions)"
            showMemoryUsage

            $batch.Group | ForEach-Object -Parallel {
                $startSubLoopThis = Get-Date
                $childMgSubDetail = $_
                #region UsingVARs
                #Parameters MG&Sub related
                $CsvDelimiter = $using:CsvDelimiter
                $CsvDelimiterOpposite = $using:CsvDelimiterOpposite
                #Parameters Sub related
                #fromOtherFunctions
                $azAPICallConf = $using:azAPICallConf
                $scriptPath = $using:ScriptPath
                #Array&HTs
                $newTable = $using:newTable
                $resourcesAll = $using:resourcesAll
                $resourcesIdsAll = $using:resourcesIdsAll
                $resourceGroupsAll = $using:resourceGroupsAll
                $customDataCollectionDuration = $using:customDataCollectionDuration
                $htSubscriptionsMgPath = $using:htSubscriptionsMgPath
                $htManagementGroupsMgPath = $using:htManagementGroupsMgPath
                $htResourceProvidersAll = $using:htResourceProvidersAll
                $htSubscriptionTagList = $using:htSubscriptionTagList
                $htResourceTypesUniqueResource = $using:htResourceTypesUniqueResource
                $htAllTagList = $using:htAllTagList
                $htSubscriptionTags = $using:htSubscriptionTags
                $htCacheDefinitionsPolicy = $using:htCacheDefinitionsPolicy
                $htCacheDefinitionsPolicySet = $using:htCacheDefinitionsPolicySet
                $htCacheDefinitionsRole = $using:htCacheDefinitionsRole
                $htCacheDefinitionsBlueprint = $using:htCacheDefinitionsBlueprint
                $htRoleDefinitionIdsUsedInPolicy = $using:htRoleDefinitionIdsUsedInPolicy
                $htCachePolicyComplianceSUB = $using:htCachePolicyComplianceSUB
                $htCachePolicyComplianceResponseTooLargeSUB = $using:htCachePolicyComplianceResponseTooLargeSUB
                $htCacheAssignmentsRole = $using:htCacheAssignmentsRole
                $htCacheAssignmentsRBACOnResourceGroupsAndResources = $using:htCacheAssignmentsRBACOnResourceGroupsAndResources
                $htCacheAssignmentsBlueprint = $using:htCacheAssignmentsBlueprint
                $htCacheAssignmentsPolicyOnResourceGroupsAndResources = $using:htCacheAssignmentsPolicyOnResourceGroupsAndResources
                $htCacheAssignmentsPolicy = $using:htCacheAssignmentsPolicy
                $htPolicyAssignmentExemptions = $using:htPolicyAssignmentExemptions
                $htResourceLocks = $using:htResourceLocks
                $LimitPOLICYPolicyDefinitionsScopedSubscription = $using:LimitPOLICYPolicyDefinitionsScopedSubscription
                $LimitPOLICYPolicySetDefinitionsScopedSubscription = $using:LimitPOLICYPolicySetDefinitionsScopedSubscription
                $LimitPOLICYPolicyAssignmentsSubscription = $using:LimitPOLICYPolicyAssignmentsSubscription
                $LimitPOLICYPolicySetAssignmentsSubscription = $using:LimitPOLICYPolicySetAssignmentsSubscription
                $childrenSubscriptionsCount = $using:childrenSubscriptionsCount
                $subsToProcessInCustomDataCollectionCount = $using:subsToProcessInCustomDataCollectionCount
                $arrayDataCollectionProgressSub = $using:arrayDataCollectionProgressSub
                $arraySubResourcesAddArrayDuration = $using:arraySubResourcesAddArrayDuration
                $htAllSubscriptionsFromAPI = $using:htAllSubscriptionsFromAPI
                $arrayEntitiesFromAPI = $using:arrayEntitiesFromAPI
                $arrayDiagnosticSettingsMgSub = $using:arrayDiagnosticSettingsMgSub
                $htMgASCSecureScore = $using:htMgASCSecureScore
                $htRoleAssignmentsFromAPIInheritancePrevention = $using:htRoleAssignmentsFromAPIInheritancePrevention
                $htNamingValidation = $using:htNamingValidation
                $htPrincipals = $using:htPrincipals
                $htServicePrincipals = $using:htServicePrincipals
                $htUserTypesGuest = $using:htUserTypesGuest
                $arrayDefenderPlans = $using:arrayDefenderPlans
                $arrayDefenderPlansSubscriptionNotRegistered = $using:arrayDefenderPlansSubscriptionNotRegistered
                $arrayUserAssignedIdentities4Resources = $using:arrayUserAssignedIdentities4Resources
                $htSubscriptionsRoleAssignmentLimit = $using:htSubscriptionsRoleAssignmentLimit
                $PSRuleVersion = $using:PSRuleVersion
                $arrayPsRule = $using:arrayPsRule
                $arrayPSRuleTracking = $using:arrayPSRuleTracking
                #other
                $function:addRowToTable = $using:funcAddRowToTable
                $function:namingValidation = $using:funcNamingValidation
                $function:resolveObjectIds = $using:funcResolveObjectIds
                $function:dataCollectionMGSecureScore = $using:funcDataCollectionMGSecureScore
                $function:dataCollectionDefenderPlans = $using:funcDataCollectionDefenderPlans
                $function:dataCollectionDiagnosticsSub = $using:funcDataCollectionDiagnosticsSub
                $function:dataCollectionResources = $using:funcDataCollectionResources
                $function:dataCollectionResourceGroups = $using:funcDataCollectionResourceGroups
                $function:dataCollectionResourceProviders = $using:funcDataCollectionResourceProviders
                $function:dataCollectionResourceLocks = $using:funcDataCollectionResourceLocks
                $function:dataCollectionTags = $using:funcDataCollectionTags
                $function:dataCollectionPolicyComplianceStates = $using:funcDataCollectionPolicyComplianceStates
                $function:dataCollectionASCSecureScoreSub = $using:funcDataCollectionASCSecureScoreSub
                $function:dataCollectionBluePrintDefinitionsSub = $using:funcDataCollectionBluePrintDefinitionsSub
                $function:dataCollectionBluePrintAssignmentsSub = $using:funcDataCollectionBluePrintAssignmentsSub
                $function:dataCollectionPolicyExemptions = $using:funcDataCollectionPolicyExemptions
                $function:dataCollectionPolicyDefinitions = $using:funcDataCollectionPolicyDefinitions
                $function:dataCollectionPolicySetDefinitions = $using:funcDataCollectionPolicySetDefinitions
                $function:dataCollectionPolicyAssignmentsSub = $using:funcDataCollectionPolicyAssignmentsSub
                $function:dataCollectionRoleDefinitions = $using:funcDataCollectionRoleDefinitions
                $function:dataCollectionRoleAssignmentsSub = $using:funcDataCollectionRoleAssignmentsSub
                #endregion UsingVARs

                $addRowToTableDone = $false

                $childMgSubId = $childMgSubDetail.subscriptionId
                $childMgSubDisplayName = $childMgSubDetail.subscriptionName
                $hierarchyInfo = $htSubscriptionsMgPath.($childMgSubDetail.subscriptionId)
                $hierarchyLevel = $hierarchyInfo.level
                $childMgId = $hierarchyInfo.Parent
                $childMgDisplayName = $hierarchyInfo.ParentName
                $childMgMgPath = $hierarchyInfo.pathDelimited
                $childMgParentInfo = $htManagementGroupsMgPath.($childMgId)
                $childMgParentId = $childMgParentInfo.Parent
                $childMgParentName = $htManagementGroupsMgPath.($childMgParentInfo.Parent).DisplayName

                #namingValidation
                if (-not [string]::IsNullOrEmpty($childMgSubDisplayName)) {
                    $namingValidationResult = NamingValidation -toCheck $childMgSubDisplayName
                    if ($namingValidationResult.Count -gt 0) {

                        $script:htNamingValidation.Subscription.($childMgSubId) = @{}
                        $script:htNamingValidation.Subscription.($childMgSubId).displayNameInvalidChars = ($namingValidationResult -join '')
                        $script:htNamingValidation.Subscription.($childMgSubId).displayName = $childMgSubDisplayName
                    }
                }

                #$rndom = Get-Random -Minimum 10 -Maximum 750
                #start-sleep -Millisecond $rndom
                if ($azAPICallConf['htParameters'].HierarchyMapOnly -eq $false) {
                    $currentSubscription = $htAllSubscriptionsFromAPI.($childMgSubId).subDetails
                    $subscriptionQuotaId = $currentSubscription.subscriptionPolicies.quotaId
                    $subscriptionState = $currentSubscription.state

                    $targetMgOrSub = 'Sub'
                    $baseParameters = @{
                        scopeId          = $childMgSubId
                        scopeDisplayName = $childMgSubDisplayName
                    }

                    if (-not $azAPICallConf['htParameters'].ManagementGroupsOnly) {
                        #mgSecureScore
                        $mgAscSecureScoreResult = DataCollectionMGSecureScore -Id $childMgId

                        #defenderPlans
                        $dataCollectionDefenderPlansParameters = @{
                            ChildMgMgPath = $childMgMgPath
                        }
                        DataCollectionDefenderPlans @baseParameters @dataCollectionDefenderPlansParameters

                        #diagnostics
                        $dataCollectionDiagnosticsSubParameters = @{
                            ChildMgMgPath = $childMgMgPath
                            ChildMgId     = $childMgId
                        }
                        DataCollectionDiagnosticsSub @baseParameters @dataCollectionDiagnosticsSubParameters


                        if ($azAPICallConf['htParameters'].NoResources -eq $false) {
                            #resources
                            $dataCollectionResourcesParameters = @{
                                ChildMgMgPath = $childMgMgPath
                            }
                            DataCollectionResources @baseParameters @dataCollectionResourcesParameters
                        }

                        #resourceGroups
                        DataCollectionResourceGroups @baseParameters

                        #resourceProviders
                        DataCollectionResourceProviders @baseParameters

                        #resourceLocks
                        DataCollectionResourceLocks @baseParameters

                        #tags
                        $subscriptionTagsReturn = DataCollectionTags @baseParameters
                        $subscriptionTags = $subscriptionTagsReturn.subscriptionTags
                        $subscriptionTagsCount = $subscriptionTagsReturn.subscriptionTagsCount

                        if ($azAPICallConf['htParameters'].NoPolicyComplianceStates -eq $false) {
                            #SubscriptionPolicyCompliance
                            DataCollectionPolicyComplianceStates @baseParameters -TargetMgOrSub $targetMgOrSub
                        }

                        #SubscriptionASCSecureScore
                        $subscriptionASCSecureScore = DataCollectionASCSecureScoreSub @baseParameters

                        $addRowToTableParameters = @{
                            hierarchyLevel             = $hierarchyLevel
                            childMgDisplayName         = $childMgDisplayName
                            childMgId                  = $childMgId
                            childMgParentId            = $childMgParentId
                            childMgParentName          = $childMgParentName
                            mgAscSecureScoreResult     = $mgAscSecureScoreResult
                            subscriptionQuotaId        = $subscriptionQuotaId
                            subscriptionState          = $subscriptionState
                            subscriptionASCSecureScore = $subscriptionASCSecureScore
                            subscriptionTags           = $subscriptionTags
                            subscriptionTagsCount      = $subscriptionTagsCount
                        }

                        #SubscriptionBlueprintDefinitions
                        $functionReturn = DataCollectionBluePrintDefinitionsSub @baseParameters @addRowToTableParameters
                        if ($functionReturn.'addRowToTableDone') {
                            $addRowToTableDone = $true
                        }

                        #SubscriptionBlueprintAssignments
                        $functionReturn = DataCollectionBluePrintAssignmentsSub @baseParameters @addRowToTableParameters
                        if ($functionReturn.'addRowToTableDone') {
                            $addRowToTableDone = $true
                        }

                        #SubscriptionPolicyExemptions
                        DataCollectionPolicyExemptions @baseParameters -TargetMgOrSub $targetMgOrSub

                        #SubscriptionPolicyDefinitions
                        $functionReturn = DataCollectionPolicyDefinitions @baseParameters -TargetMgOrSub $targetMgOrSub
                        $policyDefinitionsScopedCount = $functionReturn.'PolicyDefinitionsScopedCount'

                        #SubscriptionPolicySets
                        $functionReturn = DataCollectionPolicySetDefinitions @baseParameters -TargetMgOrSub $targetMgOrSub
                        $policySetDefinitionsScopedCount = $functionReturn.'PolicySetDefinitionsScopedCount'

                        $scopedPolicyCounts = @{
                            policyDefinitionsScopedCount    = $policyDefinitionsScopedCount
                            policySetDefinitionsScopedCount = $policySetDefinitionsScopedCount
                        }

                        #SubscriptionPolicyAssignments
                        $functionReturn = DataCollectionPolicyAssignmentsSub @baseParameters @addRowToTableParameters @scopedPolicyCounts
                        if ($functionReturn.'addRowToTableDone') {
                            $addRowToTableDone = $true
                        }

                        #SubscriptionRoleDefinitions
                        DataCollectionRoleDefinitions @baseParameters -TargetMgOrSub $targetMgOrSub

                        #SubscriptionRoleAssignments
                        $functionReturn = DataCollectionRoleAssignmentsSub @baseParameters @addRowToTableParameters
                        if ($functionReturn.'addRowToTableDone') {
                            $addRowToTableDone = $true
                        }
                    }

                    if ($addRowToTableDone -ne $true) {
                        addRowToTable `
                            -level $hierarchyLevel `
                            -mgName $childMgDisplayName `
                            -mgId $childMgId `
                            -mgParentId $childMgParentId `
                            -mgParentName $childMgParentName `
                            -mgASCSecureScore $mgAscSecureScoreResult `
                            -Subscription $childMgSubDisplayName `
                            -SubscriptionId $childMgSubId `
                            -SubscriptionASCSecureScore $subscriptionASCSecureScore
                    }
                }
                else {
                    addRowToTable `
                        -level $hierarchyLevel `
                        -mgName $childMgDisplayName `
                        -mgId $childMgId `
                        -mgParentId $childMgParentId `
                        -mgParentName $childMgParentName `
                        -mgASCSecureScore $mgAscSecureScoreResult `
                        -Subscription $childMgSubDisplayName `
                        -SubscriptionId $childMgSubId `
                        -SubscriptionASCSecureScore $subscriptionASCSecureScore
                }
                $endSubLoopThis = Get-Date
                $null = $script:customDataCollectionDuration.Add([PSCustomObject]@{
                        Type        = 'SUB'
                        Id          = $childMgSubId
                        DurationSec = (NEW-TIMESPAN -Start $startSubLoopThis -End $endSubLoopThis).TotalSeconds
                    })

                $null = $script:arrayDataCollectionProgressSub.Add($childMgSubId)
                $progressCount = ($arrayDataCollectionProgressSub).Count
                Write-Host "  $($progressCount)/$($subsToProcessInCustomDataCollectionCount) Subscriptions processed"

            } -ThrottleLimit $ThrottleLimit

            $endBatch = Get-Date
            Write-Host " Batch #$batchCnt processing duration: $((NEW-TIMESPAN -Start $startBatch -End $endBatch).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startBatch -End $endBatch).TotalSeconds) seconds)"
        }
        #[System.GC]::Collect()

        $endSubLoop = Get-Date
        Write-Host " CustomDataCollection Subscriptions processing duration: $((NEW-TIMESPAN -Start $startSubLoop -End $endSubLoop).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startSubLoop -End $endSubLoop).TotalSeconds) seconds)"
        if ($azAPICallConf['htParameters'].DoPSRule -eq $true) {
            if ($arrayPSRuleTracking.Count -gt 0) {
                $durationPSRuleTotalSeconds = (($arrayPSRuleTracking.duration | Measure-Object -Sum).Sum)
                Write-Host "  CustomDataCollection Subscriptions PSRule processing duration (in sum): $($durationPSRuleTotalSeconds / 60) minutes ($($durationPSRuleTotalSeconds) seconds)"
            }
        }
        #test
        Write-Host " built-in PolicyDefinitions: $($($htCacheDefinitionsPolicy).Values.where({$_.Type -eq 'BuiltIn'}).Count)"
        Write-Host " custom PolicyDefinitions: $($($htCacheDefinitionsPolicy).Values.where({$_.Type -eq 'Custom'}).Count)"
        Write-Host " all PolicyDefinitions: $($($htCacheDefinitionsPolicy).Values.Count)"
    }
    #endregion SUBSCRIPTION

    $durationDataMG = $customDataCollectionDuration.where( { $_.Type -eq 'MG' } )
    $durationDataSUB = $customDataCollectionDuration.where( { $_.Type -eq 'SUB' } )
    $durationMGAverageMaxMin = ($durationDataMG.DurationSec | Measure-Object -Average -Maximum -Minimum)
    $durationSUBAverageMaxMin = ($durationDataSUB.DurationSec | Measure-Object -Average -Maximum -Minimum)
    Write-Host "Collecting custom data for $($arrayEntitiesFromAPIManagementGroupsCount) ManagementGroups Avg/Max/Min duration in seconds: Average: $([math]::Round($durationMGAverageMaxMin.Average,4)); Maximum: $([math]::Round($durationMGAverageMaxMin.Maximum,4)); Minimum: $([math]::Round($durationMGAverageMaxMin.Minimum,4))"
    Write-Host "Collecting custom data for $($arrayEntitiesFromAPISubscriptionsCount) Subscriptions Avg/Max/Min duration in seconds: Average: $([math]::Round($durationSUBAverageMaxMin.Average,4)); Maximum: $([math]::Round($durationSUBAverageMaxMin.Maximum,4)); Minimum: $([math]::Round($durationSUBAverageMaxMin.Minimum,4))"

    apiCallTracking -stage 'CustomDataCollection ManagementGroups and Subscriptions' -spacing ' '

    if ($azAPICallConf['htParameters'].NoResources -eq $false) {

        $script:resourcesAllGroupedBySubcriptionId = $resourcesAll | Group-Object -property subscriptionId

        $totaldurationSubResourcesAddArray = ($arraySubResourcesAddArrayDuration.DurationSec | Measure-Object -sum).Sum
        Write-Host "Collecting custom data total duration writing the subResourcesArray: $totaldurationSubResourcesAddArray seconds"

        if (-not $azAPICallConf['htParameters'].HierarchyMapOnly -and -not $azAPICallConf['htParameters'].ManagementGroupsOnly) {
            if (-not $NoCsvExport) {
                #DataCollection Export of All Resources
                Write-Host "Exporting ResourcesAll CSV '$($outputPath)$($DirectorySeparatorChar)$($fileName)_ResourcesAll.csv'"
                $resourcesIdsAll | Sort-Object -Property id | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName)_ResourcesAll.csv" -Delimiter "$csvDelimiter" -NoTypeInformation
            }
        }
    }

    if ($azAPICallConf['htParameters'].LargeTenant -eq $false -or $azAPICallConf['htParameters'].PolicyAtScopeOnly -eq $false -or $azAPICallConf['htParameters'].RBACAtScopeOnly -eq $false) {
        if (($azAPICallConf['checkContext']).Tenant.Id -ne $ManagementGroupId) {
            addRowToTable `
                -level (($htManagementGroupsMgPath.($ManagementGroupId).ParentNameChain | Measure-Object).Count - 1) `
                -mgName $getMgParentName `
                -mgId $getMgParentId `
                -mgParentId "'upperScopes'" `
                -mgParentName 'upperScopes'
        }
    }

    if ($azAPICallConf['htParameters'].LargeTenant -eq $true -or $azAPICallConf['htParameters'].PolicyAtScopeOnly -eq $true) {
        if (($azAPICallConf['checkContext']).Tenant.Id -ne $ManagementGroupId) {
            $currentTask = "Policy assignments ('$($ManagementGroupId)')"
            $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/providers/Microsoft.Management/managementgroups/$($ManagementGroupId)/providers/Microsoft.Authorization/policyAssignments?`$filter=atScope()&api-version=2021-06-01"
            $method = 'GET'
            $upperScopesPolicyAssignments = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -caller 'CustomDataCollection'

            $upperScopesPolicyAssignments = $upperScopesPolicyAssignments | where-object { $_.properties.scope -ne "/providers/Microsoft.Management/managementGroups/$($ManagementGroupId)" }
            $upperScopesPolicyAssignmentsPolicyCount = (($upperScopesPolicyAssignments | Where-Object { $_.properties.policyDefinitionId -match '/providers/Microsoft.Authorization/policyDefinitions/' })).count
            $upperScopesPolicyAssignmentsPolicySetCount = (($upperScopesPolicyAssignments | Where-Object { $_.properties.policyDefinitionId -match '/providers/Microsoft.Authorization/policySetDefinitions/' })).count
            $upperScopesPolicyAssignmentsPolicyAtScopeCount = (($upperScopesPolicyAssignments | Where-Object { $_.properties.policyDefinitionId -match '/providers/Microsoft.Authorization/policyDefinitions/' -and $_.Id -match "/providers/Microsoft.Management/managementGroups/$($ManagementGroupId)" })).count
            $upperScopesPolicyAssignmentsPolicySetAtScopeCount = (($upperScopesPolicyAssignments | Where-Object { $_.properties.policyDefinitionId -match '/providers/Microsoft.Authorization/policySetDefinitions/' -and $_.Id -match "/providers/Microsoft.Management/managementGroups/$($ManagementGroupId)" })).count
            $upperScopesPolicyAssignmentsPolicyAndPolicySetAtScopeCount = ($upperScopesPolicyAssignmentsPolicyAtScopeCount + $upperScopesPolicyAssignmentsPolicySetAtScopeCount)
            foreach ($L0mgmtGroupPolicyAssignment in $upperScopesPolicyAssignments) {

                if ($L0mgmtGroupPolicyAssignment.properties.policyDefinitionId -match '/providers/Microsoft.Authorization/policyDefinitions/' -OR $L0mgmtGroupPolicyAssignment.properties.policyDefinitionId -match '/providers/Microsoft.Authorization/policySetDefinitions/') {
                    if ($L0mgmtGroupPolicyAssignment.properties.policyDefinitionId -match '/providers/Microsoft.Authorization/policyDefinitions/') {
                        $PolicyVariant = 'Policy'
                        $Id = ($L0mgmtGroupPolicyAssignment.properties.policydefinitionid).ToLower()
                        $Def = ($htCacheDefinitionsPolicy).($Id)
                        $PolicyAssignmentScope = $L0mgmtGroupPolicyAssignment.Properties.Scope
                        #$PolicyAssignmentNotScopes = $L0mgmtGroupPolicyAssignment.Properties.NotScopes -join "$CsvDelimiterOpposite "
                        $PolicyAssignmentId = ($L0mgmtGroupPolicyAssignment.Id).ToLower()
                        $PolicyAssignmentName = $L0mgmtGroupPolicyAssignment.Name
                        $PolicyAssignmentDisplayName = $L0mgmtGroupPolicyAssignment.Properties.DisplayName
                        if (($L0mgmtGroupPolicyAssignment.Properties.Description).length -eq 0) {
                            $PolicyAssignmentDescription = 'no description given'
                        }
                        else {
                            $PolicyAssignmentDescription = $L0mgmtGroupPolicyAssignment.Properties.Description
                        }

                        if ($L0mgmtGroupPolicyAssignment.identity) {
                            $PolicyAssignmentIdentity = $L0mgmtGroupPolicyAssignment.identity.principalId
                        }
                        else {
                            $PolicyAssignmentIdentity = 'n/a'
                        }

                        if ($Def.Type -eq 'Custom') {
                            $policyDefintionScope = $Def.Scope
                            $policyDefintionScopeMgSub = $Def.ScopeMgSub
                            $policyDefintionScopeId = $Def.ScopeId
                        }
                        else {
                            $policyDefintionScope = 'n/a'
                            $policyDefintionScopeMgSub = 'n/a'
                            $policyDefintionScopeId = 'n/a'
                        }

                        $assignedBy = 'n/a'
                        $createdBy = ''
                        $createdOn = ''
                        $updatedBy = ''
                        $updatedOn = ''
                        if ($L0mgmtGroupPolicyAssignment.properties.metadata) {
                            if ($L0mgmtGroupPolicyAssignment.properties.metadata.assignedBy) {
                                $assignedBy = $L0mgmtGroupPolicyAssignment.properties.metadata.assignedBy
                            }
                            if ($L0mgmtGroupPolicyAssignment.properties.metadata.createdBy) {
                                $createdBy = $L0mgmtGroupPolicyAssignment.properties.metadata.createdBy
                            }
                            if ($L0mgmtGroupPolicyAssignment.properties.metadata.createdOn) {
                                $createdOn = $L0mgmtGroupPolicyAssignment.properties.metadata.createdOn
                            }
                            if ($L0mgmtGroupPolicyAssignment.properties.metadata.updatedBy) {
                                $updatedBy = $L0mgmtGroupPolicyAssignment.properties.metadata.updatedBy
                            }
                            if ($L0mgmtGroupPolicyAssignment.properties.metadata.updatedOn) {
                                $updatedOn = $L0mgmtGroupPolicyAssignment.properties.metadata.updatedOn
                            }
                        }

                        if (($L0mgmtGroupPolicyAssignment.Properties.nonComplianceMessages.where( { -not $_.policyDefinitionReferenceId })).Message) {
                            $nonComplianceMessage = ($L0mgmtGroupPolicyAssignment.Properties.nonComplianceMessages.where( { -not $_.policyDefinitionReferenceId })).Message
                        }
                        else {
                            $nonComplianceMessage = ''
                        }

                        $formatedPolicyAssignmentParameters = ''
                        $hlp = $L0mgmtGroupPolicyAssignment.Properties.Parameters
                        if (-not [string]::IsNullOrEmpty($hlp)) {
                            $arrayPolicyAssignmentParameters = @()
                            $arrayPolicyAssignmentParameters = foreach ($parameterName in $hlp.PSObject.Properties.Name | Sort-Object) {
                                "$($parameterName)=$($hlp.($parameterName).Value -join "$($CsvDelimiter) ")"
                            }
                            $formatedPolicyAssignmentParameters = $arrayPolicyAssignmentParameters -join "$($CsvDelimiterOpposite) "
                        }

                        #mgSecureScore
                        $mgAscSecureScoreResult = ''

                        addRowToTable `
                            -level (($htManagementGroupsMgPath.($ManagementGroupId).ParentNameChain).Count - 1) `
                            -mgName $getMgParentName `
                            -mgId $getMgParentId `
                            -mgParentId "'upperScopes'" `
                            -mgParentName 'upperScopes' `
                            -mgASCSecureScore $mgAscSecureScoreResult `
                            -Policy $Def.DisplayName `
                            -PolicyDescription $Def.Description `
                            -PolicyVariant $PolicyVariant `
                            -PolicyType $Def.Type `
                            -PolicyCategory $Def.Category `
                            -PolicyDefinitionIdGuid (($Def.Id) -replace '.*/') `
                            -PolicyDefinitionId $Def.PolicyDefinitionId `
                            -PolicyDefintionScope $policyDefintionScope `
                            -PolicyDefintionScopeMgSub $policyDefintionScopeMgSub `
                            -PolicyDefintionScopeId $policyDefintionScopeId `
                            -PolicyDefinitionsScopedLimit $LimitPOLICYPolicyDefinitionsScopedManagementGroup `
                            -PolicyDefinitionsScopedCount $PolicyDefinitionsScopedCount `
                            -PolicySetDefinitionsScopedLimit $LimitPOLICYPolicySetDefinitionsScopedManagementGroup `
                            -PolicySetDefinitionsScopedCount $PolicySetDefinitionsScopedCount `
                            -PolicyDefinitionEffectDefault ($htCacheDefinitionsPolicy).(($Def.PolicyDefinitionId)).effectDefaultValue `
                            -PolicyDefinitionEffectFixed ($htCacheDefinitionsPolicy).(($Def.PolicyDefinitionId)).effectFixedValue `
                            -PolicyAssignmentScope $PolicyAssignmentScope `
                            -PolicyAssignmentScopeMgSubRg 'Mg' `
                            -PolicyAssignmentScopeName ($PolicyAssignmentScope -replace '.*/', '') `
                            -PolicyAssignmentNotScopes $L0mgmtGroupPolicyAssignment.Properties.NotScopes `
                            -PolicyAssignmentId $PolicyAssignmentId `
                            -PolicyAssignmentName $PolicyAssignmentName `
                            -PolicyAssignmentDisplayName $PolicyAssignmentDisplayName `
                            -PolicyAssignmentDescription $PolicyAssignmentDescription `
                            -PolicyAssignmentEnforcementMode $L0mgmtGroupPolicyAssignment.Properties.EnforcementMode `
                            -PolicyAssignmentNonComplianceMessages $L0mgmtGroupPolicyAssignment.Properties.nonComplianceMessages `
                            -PolicyAssignmentIdentity $PolicyAssignmentIdentity `
                            -PolicyAssignmentLimit $LimitPOLICYPolicyAssignmentsManagementGroup `
                            -PolicyAssignmentCount $upperScopesPolicyAssignmentsPolicyCount `
                            -PolicyAssignmentAtScopeCount $upperScopesPolicyAssignmentsPolicyAtScopeCount `
                            -PolicyAssignmentParameters $L0mgmtGroupPolicyAssignment.Properties.Parameters `
                            -PolicyAssignmentParametersFormated $formatedPolicyAssignmentParameters `
                            -PolicyAssignmentAssignedBy $assignedBy `
                            -PolicyAssignmentCreatedBy $createdBy `
                            -PolicyAssignmentCreatedOn $createdOn `
                            -PolicyAssignmentUpdatedBy $updatedBy `
                            -PolicyAssignmentUpdatedOn $updatedOn `
                            -PolicySetAssignmentLimit $LimitPOLICYPolicySetAssignmentsManagementGroup `
                            -PolicySetAssignmentCount $upperScopesPolicyAssignmentsPolicySetCount `
                            -PolicySetAssignmentAtScopeCount $upperScopesPolicyAssignmentsPolicySetAtScopeCount `
                            -PolicyAndPolicySetAssignmentAtScopeCount $upperScopesPolicyAssignmentsPolicyAndPolicySetAtScopeCount
                    }

                    if ($L0mgmtGroupPolicyAssignment.properties.policyDefinitionId -match '/providers/Microsoft.Authorization/policySetDefinitions/') {
                        $PolicyVariant = 'PolicySet'
                        $Id = ($L0mgmtGroupPolicyAssignment.properties.policydefinitionid).ToLower()
                        $Def = ($htCacheDefinitionsPolicySet).($Id)
                        $PolicyAssignmentScope = $L0mgmtGroupPolicyAssignment.Properties.Scope
                        #$PolicyAssignmentNotScopes = $L0mgmtGroupPolicyAssignment.Properties.NotScopes -join "$CsvDelimiterOpposite "
                        $PolicyAssignmentId = ($L0mgmtGroupPolicyAssignment.Id).ToLower()
                        $PolicyAssignmentName = $L0mgmtGroupPolicyAssignment.Name
                        $PolicyAssignmentDisplayName = $L0mgmtGroupPolicyAssignment.Properties.DisplayName
                        if (($L0mgmtGroupPolicyAssignment.Properties.Description).length -eq 0) {
                            $PolicyAssignmentDescription = 'no description given'
                        }
                        else {
                            $PolicyAssignmentDescription = $L0mgmtGroupPolicyAssignment.Properties.Description
                        }

                        if ($L0mgmtGroupPolicyAssignment.identity) {
                            $PolicyAssignmentIdentity = $L0mgmtGroupPolicyAssignment.identity.principalId
                        }
                        else {
                            $PolicyAssignmentIdentity = 'n/a'
                        }

                        if ($Def.Type -eq 'Custom') {
                            $policyDefintionScope = $Def.Scope
                            $policyDefintionScopeMgSub = $Def.ScopeMgSub
                            $policyDefintionScopeId = $Def.ScopeId
                        }
                        else {
                            $policyDefintionScope = 'n/a'
                            $policyDefintionScopeMgSub = 'n/a'
                            $policyDefintionScopeId = 'n/a'
                        }

                        $assignedBy = 'n/a'
                        $createdBy = ''
                        $createdOn = ''
                        $updatedBy = ''
                        $updatedOn = ''
                        if ($L0mgmtGroupPolicyAssignment.properties.metadata) {
                            if ($L0mgmtGroupPolicyAssignment.properties.metadata.assignedBy) {
                                $assignedBy = $L0mgmtGroupPolicyAssignment.properties.metadata.assignedBy
                            }
                            if ($L0mgmtGroupPolicyAssignment.properties.metadata.createdBy) {
                                $createdBy = $L0mgmtGroupPolicyAssignment.properties.metadata.createdBy
                            }
                            if ($L0mgmtGroupPolicyAssignment.properties.metadata.createdOn) {
                                $createdOn = $L0mgmtGroupPolicyAssignment.properties.metadata.createdOn
                            }
                            if ($L0mgmtGroupPolicyAssignment.properties.metadata.updatedBy) {
                                $updatedBy = $L0mgmtGroupPolicyAssignment.properties.metadata.updatedBy
                            }
                            if ($L0mgmtGroupPolicyAssignment.properties.metadata.updatedOn) {
                                $updatedOn = $L0mgmtGroupPolicyAssignment.properties.metadata.updatedOn
                            }
                        }

                        if (($L0mgmtGroupPolicyAssignment.Properties.nonComplianceMessages.where( { -not $_.policyDefinitionReferenceId })).Message) {
                            $nonComplianceMessage = ($L0mgmtGroupPolicyAssignment.Properties.nonComplianceMessages.where( { -not $_.policyDefinitionReferenceId })).Message
                        }
                        else {
                            $nonComplianceMessage = ''
                        }

                        $formatedPolicyAssignmentParameters = ''
                        $hlp = $L0mgmtGroupPolicyAssignment.Properties.Parameters
                        if (-not [string]::IsNullOrEmpty($hlp)) {
                            $arrayPolicyAssignmentParameters = @()
                            $arrayPolicyAssignmentParameters = foreach ($parameterName in $hlp.PSObject.Properties.Name | Sort-Object) {
                                "$($parameterName)=$($hlp.($parameterName).Value -join "$($CsvDelimiter) ")"
                            }
                            $formatedPolicyAssignmentParameters = $arrayPolicyAssignmentParameters -join "$($CsvDelimiterOpposite) "
                        }

                        addRowToTable `
                            -level (($htManagementGroupsMgPath.($ManagementGroupId).ParentNameChain).Count - 1) `
                            -mgName $getMgParentName `
                            -mgId $getMgParentId `
                            -mgParentId "'upperScopes'" `
                            -mgParentName 'upperScopes' `
                            -mgASCSecureScore $mgAscSecureScoreResult `
                            -Policy $Def.DisplayName `
                            -PolicyDescription $Def.Description `
                            -PolicyVariant $PolicyVariant `
                            -PolicyType $Def.Type `
                            -PolicyCategory $Def.Category `
                            -PolicyDefinitionIdGuid (($Def.Id) -replace '.*/') `
                            -PolicyDefinitionId $Def.PolicyDefinitionId `
                            -PolicyDefintionScope $policyDefintionScope `
                            -PolicyDefintionScopeMgSub $policyDefintionScopeMgSub `
                            -PolicyDefintionScopeId $policyDefintionScopeId `
                            -PolicyDefinitionsScopedLimit $LimitPOLICYPolicyDefinitionsScopedManagementGroup `
                            -PolicyDefinitionsScopedCount $PolicyDefinitionsScopedCount `
                            -PolicySetDefinitionsScopedLimit $LimitPOLICYPolicySetDefinitionsScopedManagementGroup `
                            -PolicySetDefinitionsScopedCount $PolicySetDefinitionsScopedCount `
                            -PolicyAssignmentScope $PolicyAssignmentScope `
                            -PolicyAssignmentScopeMgSubRg 'Mg' `
                            -PolicyAssignmentScopeName ($PolicyAssignmentScope -replace '.*/', '') `
                            -PolicyAssignmentNotScopes $L0mgmtGroupPolicyAssignment.Properties.NotScopes `
                            -PolicyAssignmentId $PolicyAssignmentId `
                            -PolicyAssignmentName $PolicyAssignmentName `
                            -PolicyAssignmentDisplayName $PolicyAssignmentDisplayName `
                            -PolicyAssignmentDescription $PolicyAssignmentDescription `
                            -PolicyAssignmentEnforcementMode $L0mgmtGroupPolicyAssignment.Properties.EnforcementMode `
                            -PolicyAssignmentNonComplianceMessages $L0mgmtGroupPolicyAssignment.Properties.nonComplianceMessages `
                            -PolicyAssignmentIdentity $PolicyAssignmentIdentity `
                            -PolicyAssignmentLimit $LimitPOLICYPolicyAssignmentsManagementGroup `
                            -PolicyAssignmentCount $upperScopesPolicyAssignmentsPolicyCount `
                            -PolicyAssignmentAtScopeCount $upperScopesPolicyAssignmentsPolicyAtScopeCount `
                            -PolicyAssignmentParameters $L0mgmtGroupPolicyAssignment.Properties.Parameters `
                            -PolicyAssignmentParametersFormated $formatedPolicyAssignmentParameters `
                            -PolicyAssignmentAssignedBy $assignedBy `
                            -PolicyAssignmentCreatedBy $createdBy `
                            -PolicyAssignmentCreatedOn $createdOn `
                            -PolicyAssignmentUpdatedBy $updatedBy `
                            -PolicyAssignmentUpdatedOn $updatedOn `
                            -PolicySetAssignmentLimit $LimitPOLICYPolicySetAssignmentsManagementGroup `
                            -PolicySetAssignmentCount $upperScopesPolicyAssignmentsPolicySetCount `
                            -PolicySetAssignmentAtScopeCount $upperScopesPolicyAssignmentsPolicySetAtScopeCount `
                            -PolicyAndPolicySetAssignmentAtScopeCount $upperScopesPolicyAssignmentsPolicyAndPolicySetAtScopeCount
                    }
                }
            }
        }
    }

    if ($azAPICallConf['htParameters'].LargeTenant -eq $true -or $azAPICallConf['htParameters'].RBACAtScopeOnly -eq $true) {

        #RoleAssignment API (system metadata e.g. createdOn)
        $currentTask = "Role assignments API '$($ManagementGroupId)'"
        $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/providers/Microsoft.Management/managementGroups/$($ManagementGroupId)/providers/Microsoft.Authorization/roleAssignments?api-version=2015-07-01"
        $method = 'GET'
        $roleAssignmentsFromAPI = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask

        if ($roleAssignmentsFromAPI.Count -gt 0) {
            $principalsToResolve = @()
            $principalsToResolve = foreach ($ra in $roleAssignmentsFromAPI.properties | Sort-Object -Property principalId -Unique) {
                if (-not $htPrincipals.($ra.principalId)) {
                    $ra.principalId
                }
            }

            if ($principalsToResolve.Count -gt 0) {
                ResolveObjectIds -objectIds $principalsToResolve
            }
        }

        #$upperScopesRoleAssignments = GetRoleAssignments -Scope "/providers/Microsoft.Management/managementGroups/$($ManagementGroupId)" -scopeDetails "getRoleAssignments upperScopes (Mg)"
        $upperScopesRoleAssignments = $roleAssignmentsFromAPI

        $upperScopesRoleAssignmentsLimitUtilization = (($upperScopesRoleAssignments | Where-Object { $_.properties.scope -eq "/providers/Microsoft.Management/managementGroups/$($ManagementGroupId)" })).count
        #tenantLevelRoleAssignments
        if (-not $htMgAtScopeRoleAssignments.'tenantLevelRoleAssignments') {
            $tenantLevelRoleAssignmentsCount = (($upperScopesRoleAssignments | Where-Object { $_.id -like '/providers/Microsoft.Authorization/roleAssignments/*' })).count
            $htMgAtScopeRoleAssignments.'tenantLevelRoleAssignments' = @{}
            $htMgAtScopeRoleAssignments.'tenantLevelRoleAssignments'.AssignmentsCount = $tenantLevelRoleAssignmentsCount
        }

        foreach ($upperScopesRoleAssignment in $upperScopesRoleAssignments) {

            $roleAssignmentId = ($upperScopesRoleAssignment.id).ToLower()

            if ($upperScopesRoleAssignment.properties.scope -ne "/providers/Microsoft.Management/managementGroups/$ManagementGroupId") {
                $roleDefinitionId = $upperScopesRoleAssignment.properties.roleDefinitionId
                $roleDefinitionIdGuid = $roleDefinitionId -replace '.*/'

                if (-not ($htCacheDefinitionsRole).($roleDefinitionIdGuid)) {
                    $roleDefinitionName = "'This roleDefinition likely was deleted although a roleAssignment existed'"
                }
                else {
                    $roleDefinitionName = ($htCacheDefinitionsRole).($roleDefinitionIdGuid).Name
                }

                if (($htPrincipals.($upperScopesRoleAssignment.properties.principalId).displayName).length -eq 0) {
                    $roleAssignmentIdentityDisplayname = 'n/a'
                }
                else {
                    if ($htPrincipals.($upperScopesRoleAssignment.properties.principalId).type -eq 'User') {
                        if ($azAPICallConf['htParameters'].DoNotShowRoleAssignmentsUserData -eq $false) {
                            $roleAssignmentIdentityDisplayname = $htPrincipals.($upperScopesRoleAssignment.properties.principalId).displayName
                        }
                        else {
                            $roleAssignmentIdentityDisplayname = 'scrubbed'
                        }
                    }
                    else {
                        $roleAssignmentIdentityDisplayname = $htPrincipals.($upperScopesRoleAssignment.properties.principalId).displayName
                    }
                }
                if (-not $htPrincipals.($upperScopesRoleAssignment.properties.principalId).signInName) {
                    $roleAssignmentIdentitySignInName = 'n/a'
                }
                else {
                    if ($htPrincipals.($upperScopesRoleAssignment.properties.principalId).type -eq 'User') {
                        if ($azAPICallConf['htParameters'].DoNotShowRoleAssignmentsUserData -eq $false) {
                            $roleAssignmentIdentitySignInName = $htPrincipals.($upperScopesRoleAssignment.properties.principalId).signInName
                        }
                        else {
                            $roleAssignmentIdentitySignInName = 'scrubbed'
                        }
                    }
                    else {
                        $roleAssignmentIdentitySignInName = $htPrincipals.($upperScopesRoleAssignment.properties.principalId).signInName
                    }
                }
                $roleAssignmentIdentityObjectId = $upperScopesRoleAssignment.properties.principalId
                $roleAssignmentIdentityObjectType = $htPrincipals.($upperScopesRoleAssignment.properties.principalId).type

                $roleAssignmentScope = $upperScopesRoleAssignment.properties.scope
                $roleAssignmentScopeName = $roleAssignmentScope -replace '.*/'
                $roleAssignmentScopeType = 'MG'

                $roleSecurityCustomRoleOwner = 0
                if (($htCacheDefinitionsRole).$($roleDefinitionIdGuid).Actions -eq '*' -and ((($htCacheDefinitionsRole).$($roleDefinitionIdGuid).NotActions)).length -eq 0 -and ($htCacheDefinitionsRole).$($roleDefinitionIdGuid).IsCustom -eq $True) {
                    $roleSecurityCustomRoleOwner = 1
                }
                $roleSecurityOwnerAssignmentSP = 0
                if ((($htCacheDefinitionsRole).$($roleDefinitionIdGuid).Id -eq '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' -and $roleAssignmentIdentityObjectType -eq 'ServicePrincipal') -or (($htCacheDefinitionsRole).$($roleDefinitionIdGuid).Actions -eq '*' -and ((($htCacheDefinitionsRole).$($roleDefinitionIdGuid).NotActions)).length -eq 0 -and ($htCacheDefinitionsRole).$($roleDefinitionIdGuid).IsCustom -eq $True -and $roleAssignmentIdentityObjectType -eq 'ServicePrincipal')) {
                    $roleSecurityOwnerAssignmentSP = 1
                }

                $createdBy = ''
                $createdOn = ''
                $createdOnUnformatted = $null
                $updatedBy = ''
                $updatedOn = ''

                if ($upperScopesRoleAssignment.properties.createdBy) {
                    $createdBy = $upperScopesRoleAssignment.properties.createdBy
                }
                if ($upperScopesRoleAssignment.properties.createdOn) {
                    $createdOn = $upperScopesRoleAssignment.properties.createdOn
                }
                if ($upperScopesRoleAssignment.properties.updatedBy) {
                    $updatedBy = $upperScopesRoleAssignment.properties.updatedBy
                }
                if ($upperScopesRoleAssignment.properties.updatedOn) {
                    $updatedOn = $upperScopesRoleAssignment.properties.updatedOn
                }
                $createdOnUnformatted = $upperScopesRoleAssignment.properties.createdOn

                if (($azAPICallConf['checkContext']).Tenant.Id -ne $ManagementGroupId) {
                    $levelToUse = (($htManagementGroupsMgPath.($ManagementGroupId).ParentNameChain).Count - 1)
                    $toUseAsmgName = $getMgParentName
                    $toUseAsmgId = $getMgParentId
                    $toUseAsmgParentId = "'upperScopes'"
                    $toUseAsmgParentName = 'upperScopes'
                }
                else {
                    $levelToUse = (($htManagementGroupsMgPath.($ManagementGroupId).ParentNameChain).Count)
                    $toUseAsmgName = $selectedManagementGroupId.DisplayName
                    $toUseAsmgId = $selectedManagementGroupId.Name
                    $toUseAsmgParentId = 'Tenant'
                    $toUseAsmgParentName = 'Tenant'
                }

                #mgSecureScore
                $mgAscSecureScoreResult = ''

                addRowToTable `
                    -level $levelToUse `
                    -mgName $toUseAsmgName `
                    -mgId $toUseAsmgId `
                    -mgParentId $toUseAsmgParentId `
                    -mgParentName $toUseAsmgParentName `
                    -mgASCSecureScore $mgAscSecureScoreResult `
                    -RoleDefinitionId $roleDefinitionIdGuid `
                    -RoleDefinitionName $roleDefinitionName `
                    -RoleIsCustom ($htCacheDefinitionsRole).$($roleDefinitionIdGuid).IsCustom `
                    -RoleAssignableScopes (($htCacheDefinitionsRole).$($roleDefinitionIdGuid).AssignableScopes -join "$CsvDelimiterOpposite ") `
                    -RoleActions (($htCacheDefinitionsRole).$($roleDefinitionIdGuid).Actions -join "$CsvDelimiterOpposite ") `
                    -RoleNotActions (($htCacheDefinitionsRole).$($roleDefinitionIdGuid).NotActions -join "$CsvDelimiterOpposite ") `
                    -RoleDataActions (($htCacheDefinitionsRole).$($roleDefinitionIdGuid).DataActions -join "$CsvDelimiterOpposite ") `
                    -RoleNotDataActions (($htCacheDefinitionsRole).$($roleDefinitionIdGuid).NotDataActions -join "$CsvDelimiterOpposite ") `
                    -RoleAssignmentIdentityDisplayname $roleAssignmentIdentityDisplayname `
                    -RoleAssignmentIdentitySignInName $roleAssignmentIdentitySignInName `
                    -RoleAssignmentIdentityObjectId $roleAssignmentIdentityObjectId `
                    -RoleAssignmentIdentityObjectType $roleAssignmentIdentityObjectType `
                    -RoleAssignmentId $roleAssignmentId `
                    -RoleAssignmentScope $roleAssignmentScope `
                    -RoleAssignmentScopeName $roleAssignmentScopeName `
                    -RoleAssignmentScopeType $roleAssignmentScopeType `
                    -RoleAssignmentCreatedBy $createdBy `
                    -RoleAssignmentCreatedOn $createdOn `
                    -RoleAssignmentCreatedOnUnformatted $createdOnUnformatted `
                    -RoleAssignmentUpdatedBy $updatedBy `
                    -RoleAssignmentUpdatedOn $updatedOn `
                    -RoleAssignmentsLimit $LimitRBACRoleAssignmentsManagementGroup `
                    -RoleAssignmentsCount $upperScopesRoleAssignmentsLimitUtilization `
                    -RoleSecurityCustomRoleOwner $roleSecurityCustomRoleOwner `
                    -RoleSecurityOwnerAssignmentSP $roleSecurityOwnerAssignmentSP `
                    -RoleAssignmentPIM 'unknown'
            }
        }
    }
}