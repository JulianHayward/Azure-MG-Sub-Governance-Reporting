#region HTML
function HierarchyMgHTML($mgChild) {
    $mgDetails = $htMgDetails.($mgChild).details
    $mgName = $mgDetails.mgName
    $mgId = $mgDetails.MgId

    if ($mgId -eq ($azAPICallConf['checkContext']).Tenant.Id) {
        if ($mgId -eq $defaultManagementGroupId) {
            $class = "class=`"tenantRootGroup mgnonradius defaultMG`""
        }
        else {
            $class = "class=`"tenantRootGroup mgnonradius`""
        }
    }
    else {
        if ($mgId -eq $defaultManagementGroupId) {
            $class = "class=`"mgnonradius defaultMG`""
        }
        else {
            $class = "class=`"mgnonradius`""
        }
        $liclass = ''
        $liId = ''
    }
    if ($mgName -eq $mgId) {
        $mgNameAndOrId = $mgName -replace '<', '&lt;' -replace '>', '&gt;'
    }
    else {
        $mgNameAndOrId = "$($mgName -replace '<', '&lt;' -replace '>', '&gt;')<br><i>$mgId</i>"
    }

    $mgPolicyAssignmentCount = 0
    if ($htMgAtScopePolicyAssignments.($mgId)) {
        $mgPolicyAssignmentCount = $htMgAtScopePolicyAssignments.($mgId).AssignmentsCount
    }
    $mgPolicyPolicySetScopedCount = 0
    if ($htMgAtScopePoliciesScoped.($mgId)) {
        $mgPolicyPolicySetScopedCount = $htMgAtScopePoliciesScoped.($mgId).ScopedCount
    }
    $mgIdRoleAssignmentCount = 0
    if ($htMgAtScopeRoleAssignments.($mgId)) {
        $mgIdRoleAssignmentCount = $htMgAtScopeRoleAssignments.($mgId).AssignmentsCount
    }
    $script:html += @"
                    <li $liId $liclass>
                        <a $class href="#table_$mgId" id="hierarchy_$mgId">
                            <div class="main">

                                <div class="extraInfo">
                                    <div class="extraInfoContent">
"@
    if ($mgPolicyAssignmentCount -gt 0 -or $mgPolicyPolicySetScopedCount -gt 0) {
        if ($mgPolicyAssignmentCount -gt 0 -and $mgPolicyPolicySetScopedCount -gt 0) {
            $script:html += @"
                                        <div class="extraInfoPolicyAss1">
                                            <abbr class="abbrTree" title="$($mgPolicyAssignmentCount) Policy assignments">$($mgPolicyAssignmentCount)</abbr>
                                        </div>
                                        <div class="extraInfoPolicyScoped1">
                                            <abbr class="abbrTree" title="$($mgPolicyPolicySetScopedCount) Policy/PolicySet definitions scoped">$($mgPolicyPolicySetScopedCount)</abbr>
                                        </div>
"@
        }
        else {
            if ($mgPolicyAssignmentCount -gt 0) {
                $script:html += @"
                                            <div class="extraInfoPolicyAss0">
                                                <abbr class="abbrTree" title="$($mgPolicyAssignmentCount) Policy assignments">$($mgPolicyAssignmentCount)</abbr>
                                            </div>
"@
            }
            if ($mgPolicyPolicySetScopedCount -gt 0) {
                $script:html += @"
                                            <div class="extraInfoPolicyScoped0">
                                                <abbr class="abbrTree" title="$($mgPolicyPolicySetScopedCount) Policy/PolicySet definitions scoped">$($mgPolicyPolicySetScopedCount)</abbr>
                                            </div>
"@
            }
        }
    }
    else {
        $script:html += @'
    <div class="extraInfoPlchldr"></div>
'@
    }
    $script:html += @'
                                            </div>
                                            <div class="treeMgLogo">
                                                <img class="imgTreeLogo" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-11-Management-Groups.svg">
                                            </div>
                                            <div class="extraInfoContent">
'@
    if ($mgIdRoleAssignmentCount -gt 0) {
        $script:html += @"
                                            <div class="extraInfoRoleAss">
                                                <abbr class="abbrTree" title="$($mgIdRoleAssignmentCount) Role assignments">$($mgIdRoleAssignmentCount)</abbr>
                                            </div>
"@
    }
    else {
        $script:html += @'
    <div class="extraInfoPlchldr"></div>
'@
    }
    $script:html += @"
                                    </div>
                                </div>

                                <div class="fitme" id="fitme">$($mgNameAndOrId)
                                </div>
                            </div>
                        </a>
"@
    $childMgs = $htMgDetails.($mgId).mgChildren
    if (($childMgs).count -gt 0) {
        $script:html += @'
                <ul>
'@
        foreach ($childMg in $childMgs) {
            HierarchyMgHTML -mgChild $childMg
        }
        HierarchySubForMgHTML -mgChild $mgId
        $script:html += @'
                </ul>
            </li>
'@
    }
    else {
        HierarchySubForMgUlHTML -mgChild $mgId
        $script:html += @'
            </li>
'@
    }
}

function HierarchySubForMgHTML($mgChild) {
    $subscriptions = $htMgDetails.($mgChild).Subscriptions.SubScriptionId
    $subscriptionsCnt = ($subscriptions).count
    $subscriptionsOutOfScopelinked = $outOfScopeSubscriptions.where( { $_.ManagementGroupId -eq $mgChild } )
    $subscriptionsOutOfScopelinkedCnt = ($subscriptionsOutOfScopelinked).count
    Write-Host "  Building HierarchyMap for MG '$mgChild', $($subscriptionsCnt) Subscriptions"
    if ($subscriptionsCnt -gt 0 -or $subscriptionsOutOfScopelinkedCnt -gt 0) {
        if ($subscriptionsCnt -gt 0 -and $subscriptionsOutOfScopelinkedCnt -gt 0) {
            $script:html += @"
            <li><a href="#table_$mgChild"><div class="hierarchyTreeSubs" id="hierarchySub_$mgChild"><img class="imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions.svg">$(($subscriptions).count)x <img class="imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions_excluded_r.svg">$(($subscriptionsOutOfScopelinked).count)x</div></a></li>
"@
        }
        if ($subscriptionsCnt -gt 0 -and $subscriptionsOutOfScopelinkedCnt -eq 0) {
            $script:html += @"
            <li><a href="#table_$mgChild"><div class="hierarchyTreeSubs" id="hierarchySub_$mgChild"><img class="imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions.svg"> $(($subscriptions).count)x</div></a></li>
"@
        }
        if ($subscriptionsCnt -eq 0 -and $subscriptionsOutOfScopelinkedCnt -gt 0) {
            $script:html += @"
            <li><a href="#table_$mgChild"><div class="hierarchyTreeSubs" id="hierarchySub_$mgChild"><img class="imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions_excluded_r.svg">$(($subscriptionsOutOfScopelinked).count)x</div></a></li>
"@
        }
    }
}

function HierarchySubForMgUlHTML($mgChild) {
    $subscriptions = $htMgDetails.($mgChild).Subscriptions.SubScriptionId
    $subscriptionsCnt = ($subscriptions).count
    $subscriptionsOutOfScopelinked = $outOfScopeSubscriptions.where( { $_.ManagementGroupId -eq $mgChild } )
    $subscriptionsOutOfScopelinkedCnt = ($subscriptionsOutOfScopelinked).count
    Write-Host "  Building HierarchyMap for MG '$mgChild', $($subscriptionsCnt) Subscriptions"
    if ($subscriptionsCnt -gt 0 -or $subscriptionsOutOfScopelinkedCnt -gt 0) {
        if ($subscriptionsCnt -gt 0 -and $subscriptionsOutOfScopelinkedCnt -gt 0) {
            $script:html += @"
            <ul><li><a href="#table_$mgChild"><div class="hierarchyTreeSubs" id="hierarchySub_$mgChild"><img class="imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions.svg"> $(($subscriptions).count)x <img class="imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions_excluded_r.svg">$(($subscriptionsOutOfScopelinked).count)x</div></a></li></ul>
"@
        }
        if ($subscriptionsCnt -gt 0 -and $subscriptionsOutOfScopelinkedCnt -eq 0) {
            $script:html += @"
            <ul><li><a href="#table_$mgChild"><div class="hierarchyTreeSubs" id="hierarchySub_$mgChild"><img class="imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions.svg"> $(($subscriptions).count)x</div></a></li></ul>
"@
        }
        if ($subscriptionsCnt -eq 0 -and $subscriptionsOutOfScopelinkedCnt -gt 0) {
            $script:html += @"
            <ul><li><a href="#table_$mgChild"><div class="hierarchyTreeSubs" id="hierarchySub_$mgChild"><img class="imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions_excluded_r.svg">$(($subscriptionsOutOfScopelinked).count)x</div></a></li></ul>
"@
        }
    }
}

function processScopeInsights($mgChild, $mgChildOf) {
    $mgDetails = $htMgDetails.($mgChild).details
    $mgName = $mgDetails.mgName
    $mgLevel = $mgDetails.Level
    $mgId = $mgDetails.MgId

    if (-not $NoScopeInsights) {
        if ($mgId -eq $defaultManagementGroupId) {
            $classDefaultMG = 'defaultMG'
        }
        else {
            $classDefaultMG = ''
        }

        switch ($mgLevel) {
            '0' { $levelSpacing = '| L0 &ndash;&nbsp;' }
            '1' { $levelSpacing = '| &nbsp;&nbsp;&nbsp;&nbsp;&ndash; L1 &ndash;&nbsp;' }
            '2' { $levelSpacing = '| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&ndash; &ndash; L2 &ndash;&nbsp;' }
            '3' { $levelSpacing = '| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&ndash; &ndash; &ndash; L3 &ndash;&nbsp;' }
            '4' { $levelSpacing = '| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&ndash; &ndash; &ndash; &ndash; L4 &ndash;&nbsp;' }
            '5' { $levelSpacing = '| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&ndash; &ndash; &ndash; &ndash; &ndash; L5 &ndash;&nbsp;' }
            '6' { $levelSpacing = '| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&ndash; &ndash; &ndash; &ndash; &ndash; &ndash; L6 &ndash;&nbsp;' }
        }

        $mgPath = $htManagementGroupsMgPath.($mgChild).pathDelimited

        $mgLinkedSubsCount = ((($optimizedTableForPathQuery.where( { $_.MgId -eq $mgChild -and -not [String]::IsNullOrEmpty($_.SubscriptionId) } )).SubscriptionId | Get-Unique)).count
        $subscriptionsOutOfScopelinkedCount = ($outOfScopeSubscriptions.where( { $_.ManagementGroupId -eq $mgChild } )).count
        if ($mgLinkedSubsCount -gt 0 -and $subscriptionsOutOfScopelinkedCount -eq 0) {
            $subInfo = "<img class=`"imgSub`" src=`"https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions.svg`">$mgLinkedSubsCount"
        }
        if ($mgLinkedSubsCount -gt 0 -and $subscriptionsOutOfScopelinkedCount -gt 0) {
            $subInfo = "<img class=`"imgSub`" src=`"https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions.svg`">$mgLinkedSubsCount <img class=`"imgSub`" src=`"https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions_excluded_r.svg`">$subscriptionsOutOfScopelinkedCount"
        }
        if ($mgLinkedSubsCount -eq 0 -and $subscriptionsOutOfScopelinkedCount -gt 0) {
            $subInfo = "<img class=`"imgSub`" src=`"https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions_excluded_r.svg`">$subscriptionsOutOfScopelinkedCount"
        }
        if ($mgLinkedSubsCount -eq 0 -and $subscriptionsOutOfScopelinkedCount -eq 0) {
            $subInfo = "<img class=`"imgSub`" src=`"https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions_grey.svg`">"
        }

        if ($mgName -eq $mgId) {
            $mgNameAndOrId = "$($mgName -replace '<', '&lt;' -replace '>', '&gt;')"
        }
        else {
            $mgNameAndOrId = "$($mgName -replace '<', '&lt;' -replace '>', '&gt;') ($mgId)"
        }

        $script:html += @"
<button type="button" class="collapsible" id="table_$mgId">$levelSpacing<img class="imgMg $($classDefaultMG)" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-11-Management-Groups.svg"> <span class="valignMiddle">$mgNameAndOrId $subInfo</span></button>
<div class="content">
<table class="bottomrow">
<tr><td class="detailstd"><a href="#hierarchy_$mgId"><i class="fa fa-eye" aria-hidden="true" style="color: #0078df"></i> <i><span>Highlight Management Group in HierarchyMap</span></i></a></td></tr>
"@
        if ($mgId -eq $defaultManagementGroupId) {
            $script:html += @'
        <tr><td class="detailstd"><p><i class="fa fa-circle" aria-hidden="true"></i> <b>Default</b> Management Group <a class="externallink" href="https://learn.microsoft.com/azure/governance/management-groups/how-to/protect-resource-hierarchy#setting---default-management-group" target="_blank" rel="noopener" rel="noopener">learn <i class="fa fa-external-link" aria-hidden="true"></i></a></p></td></tr>
'@
        }
        $script:html += @"
<tr><td class="detailstd"><p>Management Group Name: <b>$($mgName -replace '<', '&lt;' -replace '>', '&gt;')</b></p></td></tr>
<tr><td class="detailstd"><p>Management Group Id: <b>$mgId</b></p></td></tr>
<tr><td class="detailstd"><p>Management Group Path: $mgPath</p></td></tr>
"@
    }
    processScopeInsightsMgOrSub -mgOrSub 'mg' -mgchild $mgId
    processScopeInsightsMGSubs -mgChild $mgId
    $childMgs = $htMgDetails.($mgId).mgChildren
    if (($childMgs).count -gt 0) {
        foreach ($childMg in $childMgs) {
            processScopeInsights -mgChild $childMg -mgChildOf $mgId
        }
    }
}

function processScopeInsightsMGSubs($mgChild) {
    $subscriptions = $htMgDetails.($mgChild).Subscriptions
    $subscriptionLinkedCount = ($subscriptions).count
    $subscriptionsOutOfScopelinked = $outOfScopeSubscriptions.where( { $_.ManagementGroupId -eq $mgChild } )
    $subscriptionsOutOfScopelinkedCount = ($subscriptionsOutOfScopelinked).count
    if ($subscriptionsOutOfScopelinkedCount -gt 0) {
        $subscriptionsOutOfScopelinkedDetail = "($($subscriptionsOutOfScopelinkedCount) out-of-scope)"
    }
    else {
        $subscriptionsOutOfScopelinkedDetail = ''
    }
    Write-Host "  Building ScopeInsights MG '$mgChild', $subscriptionLinkedCount Subscriptions"

    if ($subscriptionLinkedCount -gt 0) {
        if (-not $NoScopeInsights) {
            $script:html += @"
    <tr>
        <td class="detailstd">
            <button type="button" class="collapsible"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span>$subscriptionLinkedCount Subscriptions linked $subscriptionsOutOfScopelinkedDetail</span></button>
            <div class="content"><!--collapsible-->
"@
        }
        foreach ($subEntry in $subscriptions | Sort-Object -Property subscription, subscriptionId) {
            #$subPath = $htSubscriptionsMgPath.($subEntry.subscriptionId).pathDelimited
            if ($subscriptionLinkedCount -gt 1) {
                if (-not $NoScopeInsights) {
                    $script:html += @"
                <button type="button" class="collapsible"> <img class="imgSub" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions.svg"> <span class="valignMiddle">$($subEntry.subscription -replace '<', '&lt;' -replace '>', '&gt;') ($($subEntry.subscriptionId))</span></button>
                <div class="contentSub"><!--collapsiblePerSub-->
"@
                }
            }
            #exactly 1
            else {
                if (-not $NoScopeInsights) {
                    $script:html += @"
                <img class="imgSub" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions.svg"> <span class="valignMiddle">$($subEntry.subscription -replace '<', '&lt;' -replace '>', '&gt;') ($($subEntry.subscriptionId))</span></button>
"@
                }
            }
            if (-not $NoScopeInsights) {
                $script:html += @"
                <table class="subTable">
                <tr><td class="detailstd"><a href="#hierarchySub_$mgChild"><i class="fa fa-eye" aria-hidden="true" style="color: #0078df"></i> <i><span>Highlight Subscription in HierarchyMap</span></i></a></td></tr>
"@
            }

            if (-not $azAPICallConf['htParameters'].ManagementGroupsOnly) {
                processScopeInsightsMgOrSub -mgOrSub 'sub' -subscriptionId $subEntry.subscriptionId -subscriptionsMgId $mgChild
            }

            if (-not $NoScopeInsights) {
                $script:html += @'
                </table><!--subTable-->
'@
            }
            if ($subscriptionLinkedCount -gt 1) {
                if (-not $NoScopeInsights) {
                    $script:html += @'
                </div><!--collapsiblePerSub-->
'@
                }
            }
        }
        if (-not $NoScopeInsights) {
            $script:html += @'
            </div><!--collapsible-->
'@
        }

    }
    else {
        if (-not $NoScopeInsights) {
            $script:html += @"
    <tr>
        <td class="detailstd">
            <i class="fa fa-ban" aria-hidden="true"></i> <span>$subscriptionLinkedCount Subscriptions linked $subscriptionsOutOfScopelinkedDetail</span>
"@
        }
    }
    if (-not $NoScopeInsights) {
        $script:html += @'
                </td>
            </tr>

</table>
</div>
'@
    }
}
#endregion HTML