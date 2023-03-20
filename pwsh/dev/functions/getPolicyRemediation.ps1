function getPolicyRemediation {
    $currentTask = 'Getting NonCompliant (dine/modify)'
    Write-Host $currentTask
    #ref: https://learn.microsoft.com/en-us/rest/api/azureresourcegraph/resourcegraph(2021-03-01)/resources/resources
    $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01"
    $method = 'POST'

    if ($ManagementGroupsOnly) {
        $queryNonCompliant = @'
        policyresources
        | where type == 'microsoft.policyinsights/policystates' and properties.policyAssignmentScope startswith '/providers/Microsoft.Management/managementGroups/' and (properties.policyDefinitionAction =~ 'deployifnotexists' or properties.policyDefinitionAction =~ 'modify') and properties.complianceState =~ 'NonCompliant'
        | summarize count() by assignmentScope = tostring(properties.policyAssignmentScope), assignmentName = tostring(properties.policyAssignmentName), assignmentId = tostring(properties.policyAssignmentId), definitionName = tostring(properties.policyDefinitionName), definitionId = tostring(properties.policyDefinitionId), policyDefinitionReferenceId = tostring(properties.policyDefinitionReferenceId), effect = tostring(properties.policyDefinitionAction)
        | sort by count_, assignmentId, definitionId, policyDefinitionReferenceId, effect
'@
    }
    else {
        $queryNonCompliant = @'
        policyresources
        | where (properties.policyDefinitionAction =~ 'deployifnotexists' or properties.policyDefinitionAction =~ 'modify') and properties.complianceState =~ 'NonCompliant'
        | summarize count() by assignmentScope = tostring(properties.policyAssignmentScope), assignmentName = tostring(properties.policyAssignmentName), assignmentId = tostring(properties.policyAssignmentId), definitionName = tostring(properties.policyDefinitionName), definitionId = tostring(properties.policyDefinitionId), policyDefinitionReferenceId = tostring(properties.policyDefinitionReferenceId), effect = tostring(properties.policyDefinitionAction)
        | sort by count_, assignmentId, definitionId, policyDefinitionReferenceId, effect
'@
    }


    $body = @"
    {
        "query": "$($queryNonCompliant)",
        "managementGroups":[
            "$($ManagementGroupId)"
        ],
        "options": {
            "`$top": 1000
        }
    }
"@

    $getNonCompliant = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -body $body -listenOn 'Content'
    $script:arrayRemediatable = [System.Collections.ArrayList]@()
    Write-Host " Found $($getNonCompliant.Count) remediatable Policy definitions"
    if ($getNonCompliant.Count -gt 0) {
        Write-Host ' Enriching remediatable assignments with displayNames'
        foreach ($nonCompliant in $getNonCompliant) {

            if ($htCacheAssignmentsPolicy.($nonCompliant.assignmentId.toLower())) {
                if ($htCacheAssignmentsPolicy.($nonCompliant.assignmentId.toLower()).assignment.properties.policyDefinitionId -like '*/providers/Microsoft.Authorization/policySetDefinitions/*') {
                    $policyAssignmentPolicyOrPolicySet = 'policySetDefinition'
                    $policySetDefinitionId = $htCacheAssignmentsPolicy.($nonCompliant.assignmentId.toLower()).assignment.properties.policyDefinitionId
                    $policySetDefinitionDisplayName = $htCacheDefinitionsPolicySet.($policySetDefinitionId.ToLower()).DisplayName
                    $policySetDefinitionName = $policySetDefinitionId -replace '.*/'
                    $policySetDefinitionType = $htCacheDefinitionsPolicySet.($policySetDefinitionId.ToLower()).Type
                }
                elseif ($htCacheAssignmentsPolicy.($nonCompliant.assignmentId.toLower()).assignment.properties.policyDefinitionId -like '*/providers/Microsoft.Authorization/policyDefinitions/*') {
                    $policyAssignmentPolicyOrPolicySet = 'policyDefinition'
                    $policySetDefinitionId = 'n/a'
                    $policySetDefinitionDisplayName = 'n/a'
                    $policySetDefinitionName = 'n/a'
                    $policySetDefinitionType = 'n/a'
                }
                else {
                    throw "unexpected .policyDefinitionId: $($htCacheAssignmentsPolicy.($nonCompliant.assignmentId.toLower()).assignment.properties)"
                }

                switch ($nonCompliant.assignmentId) {
                    { $_ -like '/subscriptions/*' } {
                        $policyAssignmentScopeType = 'Sub'
                    }
                    { $_ -like '/subscriptions/*/resourcegroups/*' } {
                        $policyAssignmentScopeType = 'RG'
                    }
                    { $_ -like '/providers/Microsoft.Management/managementGroups/*' } {
                        $policyAssignmentScopeType = 'MG'
                    }
                    default {
                        $policyAssignmentScopeType = 'notDetected'
                    }
                }

                $null = $script:arrayRemediatable.Add([PSCustomObject]@{
                        policyAssignmentScopeType            = $policyAssignmentScopeType
                        policyAssignmentScope                = $nonCompliant.assignmentScope
                        policyAssignmentId                   = $nonCompliant.assignmentId
                        policyAssignmentName                 = $nonCompliant.assignmentName
                        policyAssignmentDisplayName          = $htCacheAssignmentsPolicy.($nonCompliant.assignmentId.toLower()).assignment.properties.displayName
                        policyAssignmentPolicyOrPolicySet    = $policyAssignmentPolicyOrPolicySet
                        effect                               = $nonCompliant.effect
                        policyDefinitionId                   = $nonCompliant.definitionId
                        policyDefinitionName                 = $nonCompliant.definitionName
                        policyDefinitionDisplayName          = $htCacheDefinitionsPolicy.($nonCompliant.definitionId.toLower()).Json.properties.displayName
                        policyDefinitionType                 = $htCacheDefinitionsPolicy.($nonCompliant.definitionId.toLower()).Type
                        policySetPolicyDefinitionReferenceId = $nonCompliant.policyDefinitionReferenceId
                        policySetDefinitionId                = $policySetDefinitionId
                        policySetDefinitionName              = $policySetDefinitionName
                        policySetDefinitionDisplayName       = $policySetDefinitionDisplayName
                        policySetDefinitionType              = $policySetDefinitionType
                        nonCompliantResourcesCount           = $nonCompliant.count_
                    })
            }
            else {
                Write-Host "  skipping `$htCacheAssignmentsPolicy.($($nonCompliant.assignmentId)) potentially an assignment on an out-of-scope subscription"
            }
        }
    }
}
