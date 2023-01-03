function processDefinitionInsights() {
    $startDefinitionInsights = Get-Date
    Write-Host ' Building DefinitionInsights'

    $md5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
    $utf8 = New-Object -TypeName System.Text.UTF8Encoding

    #region definitionInsightsAzurePolicy
    $htmlDefinitionInsights = [System.Text.StringBuilder]::new()
    [void]$htmlDefinitionInsights.AppendLine( @'
    <button type="button" class="collapsible" id="definitionInsights_AzurePolicy"><hr class="hr-text-definitionInsightsPolicy" data-content="Policy" /></button>
    <div class="content contentDefinitionInsights">
'@)

    #policy/policySet preQuery
    #region preQuery
    $htPolicyWithAssignments = @{}
    $htPolicyWithAssignments.policy = @{}
    $htPolicyWithAssignments.policySet = @{}

    foreach ($policyOrPolicySet in $arrayPolicyAssignmentsEnriched | Sort-Object -Property PolicyAssignmentId -Unique | Group-Object -Property PolicyId, PolicyVariant) {
        $policyOrPolicySetNameSplit = $policyOrPolicySet.name.split(', ')
        if ($policyOrPolicySetNameSplit[1] -eq 'Policy') {
            #policy
            if (-not ($htPolicyWithAssignments).policy.($policyOrPolicySetNameSplit[0])) {
                $pscustomObj = [System.Collections.ArrayList]@()
                foreach ($entry in $policyOrPolicySet.group) {
                    $null = $pscustomObj.Add([PSCustomObject]@{
                            PolicyAssignmentId          = $entry.PolicyAssignmentId
                            PolicyAssignmentDisplayName = $entry.PolicyAssignmentDisplayName
                        })
                }
                ($htPolicyWithAssignments).policy.($policyOrPolicySetNameSplit[0]) = @{}
                ($htPolicyWithAssignments).policy.($policyOrPolicySetNameSplit[0]).Assignments = [array]($pscustomObj)
            }
        }
        else {
            #policySet
            if (-not ($htPolicyWithAssignments).policySet.($policyOrPolicySetNameSplit[0])) {
                $pscustomObj = [System.Collections.ArrayList]@()
                foreach ($entry in $policyOrPolicySet.group) {
                    $null = $pscustomObj.Add([PSCustomObject]@{
                            PolicyAssignmentId          = $entry.PolicyAssignmentId
                            PolicyAssignmentDisplayName = $entry.PolicyAssignmentDisplayName
                        })
                }
                ($htPolicyWithAssignments).policySet.($policyOrPolicySetNameSplit[0]) = @{}
                ($htPolicyWithAssignments).policySet.($policyOrPolicySetNameSplit[0]).Assignments = [array]($pscustomObj)
            }
        }
    }

    foreach ($customPolicy in $tenantCustomPolicies) {
        if ($htPoliciesWithAssignmentOnRgRes.($customPolicy.PolicyDefinitionId)) {
            if (-not ($htPolicyWithAssignments).policy.($customPolicy.PolicyDefinitionId)) {
                ($htPolicyWithAssignments).policy.($customPolicy.PolicyDefinitionId) = @{}
                ($htPolicyWithAssignments).policy.($customPolicy.PolicyDefinitionId).Assignments = [array]($htPoliciesWithAssignmentOnRgRes.($customPolicy.PolicyDefinitionId).Assignments)
            }
            else {
                $array = @()
                $array += ($htPolicyWithAssignments).policy.($customPolicy.PolicyDefinitionId).Assignments
                $array += $htPoliciesWithAssignmentOnRgRes.($customPolicy.PolicyDefinitionId).Assignments
                ($htPolicyWithAssignments).policy.($customPolicy.PolicyDefinitionId).Assignments = $array
            }
        }
    }

    foreach ($customPolicySet in $tenantCustomPolicySets) {
        if ($htPoliciesWithAssignmentOnRgRes.($customPolicySet.PolicyDefinitionId)) {
            if (-not ($htPolicyWithAssignments).policySet.($customPolicySet.PolicyDefinitionId)) {
                ($htPolicyWithAssignments).policySet.($customPolicySet.PolicyDefinitionId) = @{}
                ($htPolicyWithAssignments).policySet.($customPolicySet.PolicyDefinitionId).Assignments = [array]($htPoliciesWithAssignmentOnRgRes.($customPolicySet.PolicyDefinitionId).Assignments)
            }
            else {
                $array = @()
                $array += ($htPolicyWithAssignments).policySet.($customPolicySet.PolicyDefinitionId).Assignments
                $array += $htPoliciesWithAssignmentOnRgRes.($customPolicySet.PolicyDefinitionId).Assignments
                ($htPolicyWithAssignments).policySet.($customPolicySet.PolicyDefinitionId).Assignments = $array
            }
        }
    }
    #endregion preQuery

    #region definitionInsightsPolicyDefinitions
    $startDefinitionInsightsPolicyDefinitions = Get-Date
    Write-Host '  processing DefinitionInsights Policy definitions'
    ShowMemoryUsage
    $tfCount = $tenantAllPoliciesCount
    $htmlTableId = 'definitionInsights_Policy'
    [void]$htmlDefinitionInsights.AppendLine( @"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="button_definitionInsights_Policy"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$tenantAllPoliciesCount Policy definitions</span></button>
<div class="content contentDefinitionInsights">

<div id="extGridPolicy" class="panel panel-info pull-left" >
    <div class="panel-body bg-info">
        <div class="me">
            <label>Search JSON</label>
            <span id="polJson"></span>
        </div>

        <div class="me">
            <label>Builtin/Custom/Static</label>
            <span id="polType"></span>
        </div>

        <div class="me">
            <label>ALZ</label>
            <span id="polIsALZ"></span>
        </div>

        <div class="me">
            <label>Category</label>
            <span id="polCategory"></span>
        </div>

        <div class="me">
            <label>Deprecated</label>
            <span id="polDeprecated"></span>
        </div>

        <div class="me">
            <label>Preview</label>
            <span id="polPreview"></span>
        </div>

        <div class="me">
            <label>Scope Mg/Sub</label>
            <span id="polScope"></span>
        </div>

        <div class="me">
            <label>Scope Name/Id</label>
            <span id="polScopeNameId"></span>
        </div>

        <div class="me">
            <label>Effect default</label>
            <span id="polEffectDefaultValue"></span>
        </div>

        <div class="me">
            <label>hasAssignment</label>
            <span id="polHasAssignment"></span>
        </div>

        <div class="me" style="display: none;">
            <label>polPolAssignments</label>
            <span id="polPolAssignments"></span>
        </div>

        <div class="me" style="display: none;">
            <label>polhid1</label>
            <span id="polhid1"></span>
        </div>

        <div class="me">
            <label>usedInPolicySet</label>
            <span id="polUsedInPolicySet"></span>
        </div>

        <div class="me" style="display: none;">
            <label>polUsedInPolicySetCount</label>
            <span id="polUsedInPolicySetCount"></span>
        </div>

        <div class="me" style="display: none;">
            <label>polUsedInPolicySets</label>
            <span id="polUsedInPolicySets"></span>
        </div>

        <div class="me">
            <label>Roles</label>
            <span id="polRoledefs"></span>
        </div>

    </div>
</div>

<div class="pull-left" style="margin-left: 0.5em;">

<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>JSON</th>
<th>PolicyType</th>
<th>ALZ</th>
<th>Category</th>
<th>Deprecated</th>
<th>Preview</th>
<th>Scope Mg/Sub</th>
<th>Scope Name/Id</th>
<th>effectDefaultValue</th>
<th>hasAssignments</th>
<th>Assignments Count</th>
<th>Assignments</th>
<th>UsedInPolicySet</th>
<th>PolicySetsCount</th>
<th>PolicySets</th>
<th>Roles</th>
</tr>
</thead>
<tbody>
"@)

    $cnter = 0
    $htmlDefinitionInsightshlp = $null
    $htmlDefinitionInsightshlp = foreach ($policy in (($htCacheDefinitionsPolicy).Values | Sort-Object @{Expression = { $_.DisplayName } }, @{Expression = { $_.PolicyDefinitionId } })) {

        $cnter++
        if ($cnter % 1000 -eq 0) {
            Write-Host "   $cnter Policy definitions processed"
            ShowMemoryUsage
        }

        $hasAssignments = 'false'
        $assignmentsCount = 0
        $assignmentsDetailed = 'n/a'

        if (($htPolicyWithAssignments).policy.($policy.PolicyDefinitionId)) {
            $hasAssignments = 'true'
            $assignments = ($htPolicyWithAssignments).policy.($policy.PolicyDefinitionId).Assignments
            $assignmentsCount = $assignments.Count

            if ($assignmentsCount -gt 0) {
                $arrayAssignmentDetails = @()
                $arrayAssignmentDetails = foreach ($assignment in $assignments) {
                    if ($assignment.PolicyAssignmentDisplayName -eq '') {
                        $polAssDisplayName = '<i>#no AssignmentName given</i>'
                    }
                    else {
                        $polAssDisplayName = $assignment.PolicyAssignmentDisplayName
                    }
                    "$($assignment.PolicyAssignmentId) (<b>$($polAssDisplayName)</b>)"
                }
                $assignmentsDetailed = $arrayAssignmentDetails -join "$CsvDelimiterOpposite "
            }

        }

        $roleDefinitionIds = 'n/a'
        if ($policy.RoleDefinitionIds -ne 'n/a') {
            $arrayRoleDefDetails = @()
            $arrayRoleDefDetails = foreach ($roleDef in $policy.RoleDefinitionIds) {
                $roleDefIdOnly = $roleDef -replace '.*/'
                if (($roleDefIdOnly).Length -ne 36) {
                    "'INVALID RoleDefId!' ($($roleDefIdOnly))"
                }
                else {
                    $roleDefHlp = ($htCacheDefinitionsRole).($roleDefIdOnly)
                    "'$($roleDefHlp.Name)' ($($roleDefHlp.Id))"
                }
            }
            $roleDefinitionIds = $arrayRoleDefDetails -join "$CsvDelimiterOpposite "
        }

        $scopeDetails = 'n/a'
        if ($policy.ScopeId -ne 'n/a') {
            if ([string]::IsNullOrEmpty($policy.ScopeId)) {
                Write-Host "unexpected IsNullOrEmpty - processing: $($policy | ConvertTo-Json -Depth 99)"
            }
            $scopeDetails = "$($policy.ScopeId) ($($htEntities.($policy.ScopeId).DisplayName))"
        }

        $usedInPolicySet = 'false'
        $usedInPolicySetCount = 0
        $usedInPolicySets = 'n/a'

        if ($htPoliciesUsedInPolicySets.($policy.PolicyDefinitionId)) {
            $usedInPolicySet = 'true'
            $usedInPolicySetCount = ($htPoliciesUsedInPolicySets.($policy.PolicyDefinitionId).policySet).Count
            $usedInPolicySets = ($htPoliciesUsedInPolicySets.($policy.PolicyDefinitionId).policySet | Sort-Object) -join "$CsvDelimiterOpposite "
        }

        $json = $($policy.Json | ConvertTo-Json -Depth 99)
        $guid = ([System.BitConverter]::ToString($md5.ComputeHash($utf8.GetBytes($policy.PolicyDefinitionId)))) -replace '-'
        @"
<tr>
<td class="definitionInsightsjsontd">

    <div class="defCopy">
        <button class= "defCopyButton" onclick="copyDef('json$($guid)')">Copy definition</button>
            <script>
            function copyDef(elementId) {
                var copyOfTheDefinition = document.getElementById(elementId).innerText;
                navigator.clipboard.writeText(copyOfTheDefinition);
            }
        </script>
    </div>

    <div class="definitioninsightsjsondiv" id="json$($guid)"></div>

    <script>
        var jsonObj$($guid) = {};
        var jsonViewer$($guid) = new JSONViewer();
        document.querySelector("#json$($guid)").appendChild(jsonViewer$($guid).getContainer());
        var setJSON$($guid) = function() {
            try {
                jsonObj$($guid) = JSON.parse(JSON.stringify($($json)));
            }
            catch (err) {
                alert(err);
            }
        };
        setJSON$($guid)();
        jsonViewer$($guid).showJSON(jsonObj$($guid))
    </script>

</td>
<td>$($policy.Type)</td>
<td>$($policy.ALZ)</td>
<td>$($policy.Category -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($policy.Deprecated)</td>
<td>$($policy.Preview)</td>
<td>$($policy.ScopeMgSub)</td>
<td>$($scopeDetails -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($policy.effectDefaultValue)</td>
<td>$hasAssignments</td>
<td>$assignmentsCount</td>
<td class="breakwordall">$assignmentsDetailed</td>
<td class="breakwordall">$usedInPolicySet</td>
<td class="breakwordall">$usedInPolicySetCount</td>
<td class="breakwordall">$usedInPolicySets</td>
<td class="breakwordall">$($roleDefinitionIds -replace '<', '&lt;' -replace '>', '&gt;')</td>
</tr>
"@
    }
    [void]$htmlDefinitionInsights.AppendLine($htmlDefinitionInsightshlp)
    if ($NoDefinitionInsightsDedicatedHTML) {
        $htmlDefinitionInsights | Add-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).html" -Encoding utf8 -Force
        $htmlDefinitionInsights = [System.Text.StringBuilder]::new()
    }
    [void]$htmlDefinitionInsights.AppendLine( @"
    </tbody>
</table>
</div>
<script>
function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
    window.helpertfConfig4$htmlTableId =1;
    var tfConfig4$htmlTableId = {
    base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
    if ($tfCount -gt 10) {
        $spectrum = "10, $tfCount"
        if ($tfCount -gt 50) {
            $spectrum = "10, 25, 50, $tfCount"
        }
        if ($tfCount -gt 100) {
            $spectrum = "10, 30, 50, 100, $tfCount"
        }
        if ($tfCount -gt 500) {
            $spectrum = "10, 30, 50, 100, 250, $tfCount"
        }
        if ($tfCount -gt 1000) {
            $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
        }
        if ($tfCount -gt 2000) {
            $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
        }
        if ($tfCount -gt 3000) {
            $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
        }
        [void]$htmlDefinitionInsights.AppendLine( @"
        paging: {
            results_per_page: [
                'Records: ',
                [$spectrum]
            ]
        },
        /*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
    }
    [void]$htmlDefinitionInsights.AppendLine( @"
    btn_reset: true,
    highlight_keywords: true,
    alternate_rows: true,
    auto_filter: {
        delay: 1100
    },
    linked_filters: true,
    no_results_message: true,
    rows_counter: {
        text: 'results: '
    },
    col_1: 'select',
    col_2: 'select',
    col_3: 'select',
    col_4: 'select',
    col_5: 'select',
    col_6: 'select',
    col_8: 'select',
    col_9: 'select',
    col_12: 'select',
    col_types: [
        'caseinsensitivestring',
        'caseinsensitivestring',
        'caseinsensitivestring',
        'caseinsensitivestring',
        'caseinsensitivestring',
        'caseinsensitivestring',
        'caseinsensitivestring',
        'caseinsensitivestring',
        'caseinsensitivestring',
        'caseinsensitivestring',
        'number',
        'caseinsensitivestring',
        'number',
        'caseinsensitivestring',
        'caseinsensitivestring',
        'caseinsensitivestring'
    ],
    external_flt_ids: [
        'polJson',
        'polType',
        'polIsALZ',
        'polCategory',
        'polDeprecated',
        'polPreview',
        'polScope',
        'polScopeNameId',
        'polEffectDefaultValue',
        'polHasAssignment',
        'polPolAssignments',
        'polhid1',
        'polUsedInPolicySet',
        'polUsedInPolicySetCount',
        'polUsedInPolicySets',
        'polRoledefs'
    ],
    watermark: ['', '', '','', '', '', '', '', '', '', '','','','','', 'try: \'Contributor\''],
    extensions: [
        {
            name: 'sort'
        },
        {
            name: 'colsVisibility',
            at_start: [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
            text: 'Columns: ',
            enable_tick_all: true
        }
    ]
};
var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
tf.init();}}
</script>
</div>
"@)
    $endDefinitionInsightsPolicyDefinitions = Get-Date
    Write-Host "   DefinitionInsights Policy definitions duration: $((New-TimeSpan -Start $startDefinitionInsightsPolicyDefinitions -End $endDefinitionInsightsPolicyDefinitions).TotalMinutes) minutes ($((New-TimeSpan -Start $startDefinitionInsightsPolicyDefinitions -End $endDefinitionInsightsPolicyDefinitions).TotalSeconds) seconds)"
    showMemoryUsage
    #endregion definitionInsightsPolicyDefinitions

    #region definitionInsightsPolicySetDefinitions
    $startDefinitionInsightsPolicySetDefinitions = Get-Date
    Write-Host '  processing DefinitionInsights PolicySet definitions'
    ShowMemoryUsage
    $tfCount = $tenantAllPolicySetsCount
    $htmlTableId = 'definitionInsights_PolicySet'
    [void]$htmlDefinitionInsights.AppendLine( @"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="button_definitionInsights_PolicySet"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$tenantAllPolicySetsCount PolicySet definitions</span></button>
<div class="content contentDefinitionInsights">

<div id="extGridPolicySet" class="panel panel-info pull-left" >
    <div class="panel-body bg-info">
        <div class="me">
            <label>Search JSON</label>
            <span id="polsetJson"></span>
        </div>

        <div class="me">
            <label>Builtin/Custom</label>
            <span id="polsetType"></span>
        </div>

        <div class="me">
            <label>ALZ</label>
            <span id="polsetIsALZ"></span>
        </div>

        <div class="me">
            <label>Category</label>
            <span id="polsetCategory"></span>
        </div>

        <div class="me">
            <label>Deprecated</label>
            <span id="polsetDeprecated"></span>
        </div>

        <div class="me">
            <label>Preview</label>
            <span id="polsetPreview"></span>
        </div>

        <div class="me">
            <label>Scope Mg/Sub</label>
            <span id="polSetScope"></span>
        </div>

        <div class="me">
            <label>Scope Name/Id</label>
            <span id="polSetScopeNameId"></span>
        </div>

        <div class="me">
            <label>hasAssignment</label>
            <span id="polSetHasAssignment"></span>
        </div>

    </div>
</div>


<div class="pull-left" style="margin-left: 0.5em;">

<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>JSON</th>
<th>PolicySet Type</th>
<th>ALZ</th>
<th>Category</th>
<th>Deprecated</th>
<th>Preview</th>
<th>Scope Mg/Sub</th>
<th>Scope Name/Id</th>
<th>hasAssignments</th>
<th>Assignments Count</th>
<th>Assignments</th>
</tr>
</thead>
<tbody>
"@)
    $htmlDefinitionInsightshlp = $null
    $htmlDefinitionInsightshlp = foreach ($policySet in ($tenantAllPolicySets | Sort-Object @{Expression = { $_.DisplayName } }, @{Expression = { $_.PolicyDefinitionId } })) {
        $hasAssignments = 'false'
        $assignmentsCount = 0
        $assignmentsDetailed = 'n/a'

        if (($htPolicyWithAssignments).policySet.($policySet.PolicyDefinitionId)) {
            $hasAssignments = 'true'
            $assignments = ($htPolicyWithAssignments).policySet.($policySet.PolicyDefinitionId).Assignments
            $assignmentsCount = ($assignments | Measure-Object).Count

            if ($assignmentsCount -gt 0) {
                $arrayAssignmentDetails = @()
                $arrayAssignmentDetails = foreach ($assignment in $assignments) {
                    if ($assignment.PolicyAssignmentDisplayName -eq '') {
                        $polAssDisplayName = '<i>#no AssignmentName given</i>'
                    }
                    else {
                        $polAssDisplayName = $assignment.PolicyAssignmentDisplayName
                    }
                    "$($assignment.PolicyAssignmentId) (<b>$($polAssDisplayName)</b>)"
                }
                $assignmentsDetailed = $arrayAssignmentDetails -join "$CsvDelimiterOpposite "
            }
        }

        $scopeDetails = 'n/a'
        if ($policySet.ScopeId -ne 'n/a') {
            $scopeDetails = "$($policySet.ScopeId) ($($htEntities.($policySet.ScopeId).DisplayName))"
        }
        $json = $($policySet.Json | ConvertTo-Json -Depth 99)
        $guid = ([System.BitConverter]::ToString($md5.ComputeHash($utf8.GetBytes($policySet.PolicyDefinitionId)))) -replace '-'
        @"
<tr>
<td class="definitionInsightsjsontd">

    <div class="defCopy">
        <button class= "defCopyButton" onclick="copyDef('json$($guid)')">Copy definition</button>
            <script>
            function copyDef(elementId) {
                var copyOfTheDefinition = document.getElementById(elementId).innerText;
                navigator.clipboard.writeText(copyOfTheDefinition);
            }
        </script>
    </div>

    <div class="definitioninsightsjsondiv" id="json$($guid)"></div>

    <script>
        var jsonObj$($guid) = {};
        var jsonViewer$($guid) = new JSONViewer();
        document.querySelector("#json$($guid)").appendChild(jsonViewer$($guid).getContainer());
        var setJSON$($guid) = function() {
            try {
                jsonObj$($guid) = JSON.parse(JSON.stringify($($json)));
            }
            catch (err) {
                alert(err);
            }
        };
        setJSON$($guid)();
        jsonViewer$($guid).showJSON(jsonObj$($guid))
    </script>

</td>
<td>$($policySet.Type)</td>
<td>$($policySet.ALZ)</td>
<td>$($policySet.Category -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($policySet.Deprecated)</td>
<td>$($policySet.Preview)</td>
<td>$($policySet.ScopeMgSub)</td>
<td>$($scopeDetails -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$hasAssignments</td>
<td>$assignmentsCount</td>
<td class="breakwordall">$assignmentsDetailed</td>
</tr>
"@
    }
    [void]$htmlDefinitionInsights.AppendLine($htmlDefinitionInsightshlp)
    if ($NoDefinitionInsightsDedicatedHTML) {
        $htmlDefinitionInsights | Add-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).html" -Encoding utf8 -Force
        $htmlDefinitionInsights = [System.Text.StringBuilder]::new()
    }
    [void]$htmlDefinitionInsights.AppendLine( @"
    </tbody>
</table>
</div>
<script>
function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
    window.helpertfConfig4$htmlTableId =1;
    var tfConfig4$htmlTableId = {
    base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
    if ($tfCount -gt 10) {
        $spectrum = "10, $tfCount"
        if ($tfCount -gt 50) {
            $spectrum = "10, 25, 50, $tfCount"
        }
        if ($tfCount -gt 100) {
            $spectrum = "10, 30, 50, 100, $tfCount"
        }
        if ($tfCount -gt 500) {
            $spectrum = "10, 30, 50, 100, 250, $tfCount"
        }
        if ($tfCount -gt 1000) {
            $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
        }
        if ($tfCount -gt 2000) {
            $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
        }
        if ($tfCount -gt 3000) {
            $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
        }
        [void]$htmlDefinitionInsights.AppendLine( @"
        paging: {
            results_per_page: [
                'Records: ',
                [$spectrum]
            ]
        },
        /*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
    }
    [void]$htmlDefinitionInsights.AppendLine( @"
    btn_reset: true,
    highlight_keywords: true,
    alternate_rows: true,
    auto_filter: {
        delay: 1100
    },
    linked_filters: true,
    no_results_message: true,
    rows_counter: {
        text: 'results: '
    },
    col_1: 'select',
    col_2: 'select',
    col_3: 'select',
    col_4: 'select',
    col_5: 'select',
    col_6: 'select',
    col_8: 'select',
    col_types: [
        'caseinsensitivestring',
        'caseinsensitivestring',
        'caseinsensitivestring',
        'caseinsensitivestring',
        'caseinsensitivestring',
        'caseinsensitivestring',
        'caseinsensitivestring',
        'caseinsensitivestring',
        'caseinsensitivestring',
        'number',
        'caseinsensitivestring'

    ],
    external_flt_ids: [
        'polsetJson',
        'polsetType',
        'polsetIsALZ',
        'polsetCategory',
        'polsetDeprecated',
        'polsetPreview',
        'polSetScope',
        'polSetScopeNameId',
        'polSetHasAssignment'
    ],
    extensions: [
        {
            name: 'sort'
        },
        {
            name: 'colsVisibility',
            at_start: [1,2,3,4,5,6,7,8,9,10],
            text: 'Columns: ',
            enable_tick_all: true
        }
    ]
};
var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
tf.init();}}
</script>
</div>
"@)
    $endDefinitionInsightsPolicySetDefinitions = Get-Date
    Write-Host "   DefinitionInsights PolicySet definitions duration: $((New-TimeSpan -Start $startDefinitionInsightsPolicySetDefinitions -End $endDefinitionInsightsPolicySetDefinitions).TotalMinutes) minutes ($((New-TimeSpan -Start $startDefinitionInsightsPolicySetDefinitions -End $endDefinitionInsightsPolicySetDefinitions).TotalSeconds) seconds)"
    showMemoryUsage
    #endregion definitionInsightsPolicySetDefinitions

    [void]$htmlDefinitionInsights.AppendLine( @'
    </div>
'@)
    #endregion definitionInsightsAzurePolicy

    #region definitionInsightsAzureRBAC
    [void]$htmlDefinitionInsights.AppendLine( @'
    <button type="button" class="collapsible" id="definitionInsights_AzureRBAC"><hr class="hr-text-definitionInsightsRBAC" data-content="RBAC" /></button>
    <div class="content contentDefinitionInsights">
'@)

    #RBAC preQuery
    $htRoleWithAssignments = @{}
    foreach ($roleDef in $rbacAll | Sort-Object -Property RoleAssignmentId -Unique | Group-Object -Property RoleId) {
        if (-not ($htRoleWithAssignments).($roleDef.Name)) {
            ($htRoleWithAssignments).($roleDef.Name) = @{}
            ($htRoleWithAssignments).($roleDef.Name).Assignments = $roleDef.group
        }
    }

    #region definitionInsightsRoleDefinitions
    $startDefinitionInsightsRoleDefinitions = Get-Date
    Write-Host '  processing DefinitionInsights Role definitions'
    ShowMemoryUsage
    $tfCount = $tenantAllRolesCount
    $htmlTableId = 'definitionInsights_Roles'
    [void]$htmlDefinitionInsights.AppendLine( @"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="button_definitionInsights_Roles"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$tenantAllRolesCount Role definitions</span></button>
<div class="content contentDefinitionInsights">

<div id="extGridRole" class="panel panel-info pull-left" >
    <div class="panel-body bg-info">
        <div class="me">
            <label>Search JSON</label>
            <span id="roleJson"></span>
        </div>

        <div class="me">
            <label>Builtin/Custom</label>
            <span id="roleType"></span>
        </div>

        <div class="me">
            <label>Data</label>
            <span id="roleDataRelated"></span>
        </div>

        <div class="me">
            <label>canDoRoleAssignments</label>
            <span id="roleCanDoRoleAssignments"></span>
        </div>

        <div class="me">
            <label>hasAssignment</label>
            <span id="roleHasAssignment"></span>
        </div>

    </div>
</div>


<div class="pull-left" style="margin-left: 0.5em;">

<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>JSON</th>
<th>Role Type</th>
<th>Data</th>
<th>canDoRoleAssignments</th>
<th>hasAssignments</th>
<th>Assignments Count</th>
<th>Assignments</th>
</tr>
</thead>
<tbody>
"@)
    $arrayRoleDefinitionsForCSVExport = [System.Collections.ArrayList]@()
    $htmlDefinitionInsightshlp = $null
    $htmlDefinitionInsightshlp = foreach ($role in ($tenantAllRoles | Sort-Object @{Expression = { $_.Name } })) {
        if ($role.IsCustom -eq $true) {
            $roleType = 'Custom'
            $AssignableScopesCount = $role.AssignableScopes.Count
            if ($role.AssignableScopes -like '*/providers/microsoft.management/managementgroups/*') {
                $AssignableScopesMG = $true
            }
            else {
                $AssignableScopesMG = $false
            }

        }
        else {
            $roleType = 'Builtin'
            $AssignableScopesCount = ''
            $AssignableScopesMG = ''
        }
        if (-not [string]::IsNullOrEmpty($role.DataActions) -or -not [string]::IsNullOrEmpty($role.NotDataActions)) {
            $roleManageData = 'true'
        }
        else {
            $roleManageData = 'false'
        }

        $hasAssignments = 'false'
        $assignmentsCount = 0
        $assignmentsDetailed = 'n/a'
        if (($htRoleWithAssignments).($role.Id)) {
            $hasAssignments = 'true'
            $assignments = ($htRoleWithAssignments).($role.Id).Assignments
            $assignmentsCount = ($assignments).Count
            if ($assignmentsCount -gt 0) {
                $arrayAssignmentDetails = @()
                $arrayAssignmentDetails = foreach ($assignment in $assignments) {
                    "$($assignment.RoleAssignmentId)"
                }
                $assignmentsDetailed = $arrayAssignmentDetails -join "$CsvDelimiterOpposite "
            }
        }

        #array for exportCSV
        if (-not $NoCsvExport) {
            $null = $arrayRoleDefinitionsForCSVExport.Add([PSCustomObject]@{
                    Name                  = $role.Name
                    Id                    = $role.Id
                    Description           = $role.Json.description
                    Type                  = $roleType
                    AssignmentsCount      = $assignmentsCount
                    AssignableScopesCount = $AssignableScopesCount
                    AssignableScopesMG    = $AssignableScopesMG
                    AssignableScopes      = ($role.AssignableScopes | Sort-Object) -join "$CsvDelimiterOpposite "
                    DataRelated           = $roleManageData
                    RoleAssWriteCapable   = $role.RoleCanDoRoleAssignments
                    Actions               = $role.Actions -join "$CsvDelimiterOpposite "
                    NotActions            = $role.NotActions -join "$CsvDelimiterOpposite "
                    DataActions           = $role.DataActions -join "$CsvDelimiterOpposite "
                    NotDataActions        = $role.NotDataActions -join "$CsvDelimiterOpposite "
                })
        }

        $json = $role.Json | ConvertTo-Json -Depth 99
        $guid = $role.Id -replace '-'
        @"
<tr>
<td class="definitionInsightsjsontd">

    <div class="defCopy">
        <button class= "defCopyButton" onclick="copyDef('json$($guid)')">Copy definition</button>
            <script>
            function copyDef(elementId) {
                var copyOfTheDefinition = document.getElementById(elementId).innerText;
                navigator.clipboard.writeText(copyOfTheDefinition);
            }
        </script>
    </div>

    <div class="definitioninsightsjsonrbacdiv" id="json$($guid)"></div>

    <script>
        var jsonObj$($guid) = {};
        var jsonViewer$($guid) = new JSONViewer();
        document.querySelector("#json$($guid)").appendChild(jsonViewer$($guid).getContainer());
        var setJSON$($guid) = function() {
            try {
                jsonObj$($guid) = JSON.parse(JSON.stringify($($json)));
            }
            catch (err) {
                alert(err);
            }
        };
        setJSON$($guid)();
        jsonViewer$($guid).showJSON(jsonObj$($guid))
    </script>

</td>
<td>$($roleType)</td>
<td>$($roleManageData)</td>
<td>$($role.RoleCanDoRoleAssignments)</td>
<td>$hasAssignments</td>
<td>$assignmentsCount</td>
<td class="breakwordall">$assignmentsDetailed</td>
</tr>
"@
    }

    #region exportCSV
    if (-not $NoCsvExport) {
        $csvFilename = "$($filename)_RoleDefinitions"
        Write-Host "   Exporting RoleDefinitions CSV '$($outputPath)$($DirectorySeparatorChar)$($csvFilename).csv'"
        $arrayRoleDefinitionsForCSVExport | Sort-Object -Property Type, Name, Id | Export-Csv -Encoding utf8 -Path "$($outputPath)$($DirectorySeparatorChar)$($csvFilename).csv" -Delimiter $csvDelimiter -NoTypeInformation
        $arrayRoleDefinitionsForCSVExport = $null
    }
    #endregion exportCSV

    [void]$htmlDefinitionInsights.AppendLine($htmlDefinitionInsightshlp)
    if ($NoDefinitionInsightsDedicatedHTML) {
        $htmlDefinitionInsights | Add-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).html" -Encoding utf8 -Force
        $htmlDefinitionInsights = [System.Text.StringBuilder]::new()
    }
    [void]$htmlDefinitionInsights.AppendLine( @"
    </tbody>
</table>
</div>
<script>
function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
    window.helpertfConfig4$htmlTableId =1;
    var tfConfig4$htmlTableId = {
    base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
    if ($tfCount -gt 10) {
        $spectrum = "10, $tfCount"
        if ($tfCount -gt 50) {
            $spectrum = "10, 25, 50, $tfCount"
        }
        if ($tfCount -gt 100) {
            $spectrum = "10, 30, 50, 100, $tfCount"
        }
        if ($tfCount -gt 500) {
            $spectrum = "10, 30, 50, 100, 250, $tfCount"
        }
        if ($tfCount -gt 1000) {
            $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
        }
        if ($tfCount -gt 2000) {
            $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
        }
        if ($tfCount -gt 3000) {
            $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
        }
        [void]$htmlDefinitionInsights.AppendLine( @"
        paging: {
            results_per_page: [
                'Records: ',
                [$spectrum]
            ]
        },
        /*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
    }
    [void]$htmlDefinitionInsights.AppendLine( @"
    btn_reset: true,
    highlight_keywords: true,
    alternate_rows: true,
    auto_filter: {
        delay: 1100
    },
    linked_filters: true,
    no_results_message: true,
    rows_counter: {
        text: 'results: '
    },
    col_1: 'select',
    col_2: 'select',
    col_3: 'select',
    col_4: 'select',
    col_types: [
        'caseinsensitivestring',
        'caseinsensitivestring',
        'caseinsensitivestring',
        'caseinsensitivestring',
        'caseinsensitivestring',
        'number',
        'caseinsensitivestring'
    ],
    external_flt_ids: [
        'roleJson',
        'roleType',
        'roleDataRelated',
        'roleCanDoRoleAssignments',
        'roleHasAssignment'
    ],
    extensions: [
        {
            name: 'sort'
        },
        {
            name: 'colsVisibility',
            at_start: [1,2,3,4,5,6],
            text: 'Columns: ',
            enable_tick_all: true
        }
    ]
};
var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
tf.init();}}
</script>
</div>
"@)
    $endDefinitionInsightsRoleDefinitions = Get-Date
    Write-Host "   DefinitionInsights Role definitions duration: $((New-TimeSpan -Start $startDefinitionInsightsRoleDefinitions -End $endDefinitionInsightsRoleDefinitions).TotalMinutes) minutes ($((New-TimeSpan -Start $startDefinitionInsightsRoleDefinitions -End $endDefinitionInsightsRoleDefinitions).TotalSeconds) seconds)"
    showMemoryUsage
    #endregion definitionInsightsRoleDefinitions

    [void]$htmlDefinitionInsights.AppendLine( @'
    </div>
'@)
    #endregion definitionInsightsAzureRBAC

    Write-Host "   NoDefinitionInsightsDedicatedHTML: $NoDefinitionInsightsDedicatedHTML"
    if ($NoDefinitionInsightsDedicatedHTML) {
        Write-Host '   Appending DefinitionInsights to HTML'
        $script:html += $htmlDefinitionInsights
        $htmlDefinitionInsights = $null
        $script:html | Add-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).html" -Encoding utf8 -Force
        $script:html = $null
    }
    else {
        Write-Host "   Creating dedicated DefinitionInsights HTML ($($outputPath)$($DirectorySeparatorChar)$($fileName)_DefinitionInsights.html)"
        $htmlDefinitionInsightsDedicated = $null
        $htmlDefinitionInsightsDedicated += $htmlDefinitionInsightsDedicatedStart
        $htmlDefinitionInsightsDedicated += $htmlDefinitionInsights
        $htmlDefinitionInsightsDedicated += $htmlDefinitionInsightsDedicatedEnd
        #$htmlDefinitionInsights = $null
        $htmlDefinitionInsightsDedicated | Set-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName)_DefinitionInsights.html" -Encoding utf8 -Force
        #$script:htmlDefinitionInsightsDedicated = $null

        $htmlDefinitionInsightsNo = @"
        <span>DefinitionInsights has been saved to dedicated HTML file '<i>$($outputPathGiven)$($DirectorySeparatorChar)$($fileName)_DefinitionInsights.html</i>' (parameter -NoDefinitionInsightsDedicatedHTML = $($NoDefinitionInsightsDedicatedHTML))</span><br>
        Open <a class="externallink" href="$($fileName)_DefinitionInsights.html" target="blank">DefinitionInsights <i class="fa fa-external-link" aria-hidden="true"></i></a>
"@
        $script:html += $htmlDefinitionInsightsNo
        #$htmlDefinitionInsightsNo = $null
        $script:html | Add-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).html" -Encoding utf8 -Force
        $script:html = $null
    }


    $endDefinitionInsights = Get-Date
    Write-Host "  DefinitionInsights processing duration: $((New-TimeSpan -Start $startDefinitionInsights -End $endDefinitionInsights).TotalMinutes) minutes ($((New-TimeSpan -Start $startDefinitionInsights -End $endDefinitionInsights).TotalSeconds) seconds)"
    ShowMemoryUsage
}