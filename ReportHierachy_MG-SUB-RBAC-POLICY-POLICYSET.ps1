#Requires -Modules @{ ModuleName="Az"; ModuleVersion="3.3.0" }

#enter the Management Group Id from where to start
$ManagementGroupRootId = "xxx"

#helper
$csvPath = "c:\temp"
$csvFileTimestamp = get-date -format "yyyyMMddHHmmss"

<#notes
Role assignments to Unknown Object happens when the graph object(User/Group/Service principal) gets deleted from the directory after the Role assignment was created.
Since the graph entity is deleted, we cannot figure out the object's displayname or type from graph, due to which we show the objecType as Unknown.
#>


#CODE
#create table object
$table = $null
$table = New-Object system.Data.DataTable "MG Report"

#create common columns
$table.columns.add((New-Object system.Data.DataColumn Level, ([string])))
$table.columns.add((New-Object system.Data.DataColumn MgName, ([string])))
$table.columns.add((New-Object system.Data.DataColumn MgId, ([string])))
$table.columns.add((New-Object system.Data.DataColumn Subscription, ([string])))
$table.columns.add((New-Object system.Data.DataColumn SubscriptionId, ([string])))
$table.columns.add((New-Object system.Data.DataColumn Policy, ([string])))
$table.columns.add((New-Object system.Data.DataColumn PolicyType, ([string])))
$table.columns.add((New-Object system.Data.DataColumn PolicyScope, ([string])))
$table.columns.add((New-Object system.Data.DataColumn PolicyVariant, ([string])))
$table.columns.add((New-Object system.Data.DataColumn RoleDefinitionName, ([string])))
$table.columns.add((New-Object system.Data.DataColumn RoleDefinitionId, ([string])))
$table.columns.add((New-Object system.Data.DataColumn RoleIsCustom, ([string])))
$table.columns.add((New-Object system.Data.DataColumn RoleAssignmentDisplayname, ([string])))
$table.columns.add((New-Object system.Data.DataColumn RoleAssignmentSignInName, ([string])))
$table.columns.add((New-Object system.Data.DataColumn RoleAssignmentObjectId, ([string])))
$table.columns.add((New-Object system.Data.DataColumn RoleAssignmentObjectType, ([string])))
$table.columns.add((New-Object system.Data.DataColumn RoleAssignmentId, ([string])))
$table.columns.add((New-Object system.Data.DataColumn RoleAssignmentScope, ([string])))
$table.columns.add((New-Object system.Data.DataColumn RoleAssignableScopes, ([string])))

function row($l, $mgName, $mgId, $subName, $subId, $Policy, $PolicyType, $PolicyScope, $PolicyVariant, $RoleDefinitionId, $RoleDefinitionName, $RoleAssignmentDisplayname, $RoleAssignmentSignInName, $RoleAssignmentObjectId, $RoleAssignmentObjectType, $RoleAssignmentId, $RoleAssignmentScope, $RoleIsCustom, $RoleAssignableScopes) {
    $row = $table.NewRow()
    $row.Level = $l
    $row.MgName = $mgName
    $row.MgId = $mgId
    $row.Subscription = $subName
    $row.SubscriptionId = $subId
    $row.Policy = $Policy
    $row.PolicyType = $PolicyType
    $row.PolicyScope = $PolicyScope
    $row.PolicyVariant = $PolicyVariant
    $row.RoleDefinitionId = $RoleDefinitionId 
    $row.RoleDefinitionName = $RoleDefinitionName
    $row.RoleIsCustom = $RoleIsCustom
    $row.RoleAssignmentDisplayname = $RoleAssignmentDisplayname
    $row.RoleAssignmentSignInName = $RoleAssignmentSignInName
    $row.RoleAssignmentObjectId = $RoleAssignmentObjectId
    $row.RoleAssignmentObjectType = $RoleAssignmentObjectType
    $row.RoleAssignmentId = $RoleAssignmentId
    $row.RoleAssignmentScope = $RoleAssignmentScope
    $row.RoleAssignableScopes = $RoleAssignableScopes
    $table.Rows.Add($row)
}
#helper ht / collect results /save some time
$htPolicies = @{}
$htPolicySets = @{}
$htRoles = @{}
function mgfunc($mgId, $l) {
    Write-Output "...................."
    $l++
    $getMg = Get-AzManagementGroup -groupname $mgId -Expand -Recurse
    if (!$getMg){
        write-output "fail - check the provided ManagementGroup Id: '$mgI'"; break
    }
    Write-Output "Processing L$l MG-Name:'$($getMg.DisplayName)' MG-ID:'$($getMg.Name)'"
    $L0mgmtGroupPolicyAssignments = Get-AzPolicyAssignment -Scope "/providers/Microsoft.Management/managementGroups/$($getMg.Name)"
    Write-Output "MG Policy Assignments: $($L0mgmtGroupPolicyAssignments.count)"
    foreach ($L0mgmtGroupPolicyAssignment in $L0mgmtGroupPolicyAssignments) {
        if ($L0mgmtGroupPolicyAssignment.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/" -OR $L0mgmtGroupPolicyAssignment.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policySetDefinitions/") {
            $policyId = ($L0mgmtGroupPolicyAssignment.properties.policydefinitionid -replace '.*/')
            #Write-Output "PolicyId = $policyId"
            if ($L0mgmtGroupPolicyAssignment.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/") {
                #policy
                $PolicyVariant = "Policy"
                if ($L0mgmtGroupPolicyAssignment.properties.policydefinitionid -match "/providers/Microsoft.Management/managementGroups/") {
                    #custom policy
                    #Write-Output "MG custom policy"
                    if ($htPolicies[$policyId]){
                        #write-output "existing ht policy entry############################"
                    }
                    else{
                        #write-output "not existing ht policy entry"
                        $L0mgmtGroupPolicyDef = Get-AzPolicyDefinition -custom -ManagementGroupName $getMg.Name | Where-Object { $_.policydefinitionid -eq $L0mgmtGroupPolicyAssignment.properties.policydefinitionid }
                        $htPolicies.$($policyId) = @{}
                        $htPolicies.$($policyId).Id = $($L0mgmtGroupPolicyDef.name)
                        $htPolicies.$($policyId).DisplayName = $($L0mgmtGroupPolicyDef.Properties.displayname)
                        $htPolicies.$($policyId).Type = $($L0mgmtGroupPolicyDef.Properties.policyType)  
                    }   
                }
                else {
                    #Write-Output "MG built-in policy"
                    if ($htPolicies[$policyId]){
                        #write-output "existing ht policy entry############################"
                    }
                    else{
                        #write-output "not existing ht policy entry"
                        $L0mgmtGroupPolicyDef = Get-AzPolicyDefinition | Where-Object { $_.policydefinitionid -eq $L0mgmtGroupPolicyAssignment.properties.policydefinitionid }
                        $htPolicies.$($policyId) = @{}
                        $htPolicies.$($policyId).Id = $($L0mgmtGroupPolicyDef.name)
                        $htPolicies.$($policyId).DisplayName = $($L0mgmtGroupPolicyDef.Properties.displayname)  
                        $htPolicies.$($policyId).Type = $($L0mgmtGroupPolicyDef.Properties.policyType)  
                    }
                }
                $Policy = $htPolicies[$policyId].DisplayName
                $PolicyType = $htPolicies[$policyId].Type
                $PolicyScope = $L0mgmtGroupPolicyAssignment.Properties.Scope
                row -l $l -mgName $getMg.DisplayName -mgId $getMg.Name -Policy $Policy -PolicyType $PolicyType -PolicyScope $PolicyScope -PolicyVariant $PolicyVariant -RoleDefinitionId $RoleDefinitionId -RoleDefinitionName $RoleDefinitionName -RoleAssignmentDisplayname $RoleAssignmentDisplayname -RoleAssignmentSignInName $RoleAssignmentSignInName -RoleAssignmentObjectId $RoleAssignmentObjectId -RoleAssignmentObjectType $RoleAssignmentObjectType -RoleAssignmentScope $RoleAssignmentScope -RoleIsCustom $RoleIsCustom -RoleAssignableScopes $RoleAssignableScopes
                Clear-Variable -Name "Policy"
                Clear-Variable -Name "PolicyType"
                Clear-Variable -Name "PolicyScope"
                Clear-Variable -Name "PolicyVariant"
            }
            if ($L0mgmtGroupPolicyAssignment.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policySetDefinitions/") {
                $PolicyVariant = "PolicySet"
                #policySet
                if ($L0mgmtGroupPolicyAssignment.properties.policydefinitionid -match "/providers/Microsoft.Management/managementGroups/") {
                    #custom policySet
                    if ($htPolicySets[$policyId]){
                        #write-output "existing ht policySet entry############################"
                    }
                    else{
                        #write-output "not existing ht policySet entry"
                        $L0mgmtGroupPolicySetDef = Get-AzPolicySetDefinition -custom -ManagementGroupName $getMg.Name | Where-Object { $_.policysetdefinitionid -eq $L0mgmtGroupPolicyAssignment.properties.policydefinitionid }
                        $htPolicySets.$($policyId) = @{}
                        $htPolicySets.$($policyId).Id = $($L0mgmtGroupPolicySetDef.name)
                        $htPolicySets.$($policyId).DisplayName = $($L0mgmtGroupPolicySetDef.Properties.displayname)
                        $htPolicySets.$($policyId).Type = $($L0mgmtGroupPolicySetDef.Properties.policyType)  
                    }   
                }
                else {
                    if ($htPolicySets[$policyId]){
                        #write-output "existing ht policySet entry############################"
                    }
                    else{
                        #write-output "not existing ht policySet entry"
                        $L0mgmtGroupPolicySetDef = Get-AzPolicySetDefinition | Where-Object { $_.policysetdefinitionid -eq $L0mgmtGroupPolicyAssignment.properties.policydefinitionid }
                        $htPolicySets.$($policyId) = @{}
                        $htPolicySets.$($policyId).Id = $($L0mgmtGroupPolicySetDef.name)
                        $htPolicySets.$($policyId).DisplayName = $($L0mgmtGroupPolicySetDef.Properties.displayname)
                        $htPolicySets.$($policyId).Type = $($L0mgmtGroupPolicySetDef.Properties.policyType)  
                    }   
                }
                $Policy = $htPolicySets[$policyId].DisplayName
                $PolicyType = $htPolicySets[$policyId].Type
                $PolicyScope = $L0mgmtGroupPolicyAssignment.Properties.Scope
                row -l $l -mgName $getMg.DisplayName -mgId $getMg.Name -Policy $Policy -PolicyType $PolicyType -PolicyScope $PolicyScope -PolicyVariant $PolicyVariant -RoleDefinitionId $RoleDefinitionId -RoleDefinitionName $RoleDefinitionName -RoleAssignmentDisplayname $RoleAssignmentDisplayname -RoleAssignmentSignInName $RoleAssignmentSignInName -RoleAssignmentObjectId $RoleAssignmentObjectId -RoleAssignmentObjectType $RoleAssignmentObjectType -RoleAssignmentScope $RoleAssignmentScope -RoleIsCustom $RoleIsCustom -RoleAssignableScopes $RoleAssignableScopes
                Clear-Variable -Name "Policy"
                Clear-Variable -Name "PolicyType"
                Clear-Variable -Name "PolicyScope"
                Clear-Variable -Name "PolicyVariant"
            }
        }
        else {
            #s.th unexpected
            Write-Output "unexpected"
        }
    }
    $L0mgmtGroupRoleAssignments = Get-AzRoleAssignment -scope "/providers/Microsoft.Management/managementGroups/$($getMg.Name)" -verbose
    Write-Output "MG Role Assignments: $($L0mgmtGroupRoleAssignments.count)"
    foreach ($L0mgmtGroupRoleAssignment in $L0mgmtGroupRoleAssignments) {
        #Write-Output "------------------------------------------------"
        #$htRoles
        #Write-Output "------------------------------------------------"
        #Write-Output "MG Role"
        $roleId = $L0mgmtGroupRoleAssignment.RoleDefinitionId
        if ($htRoles[$L0mgmtGroupRoleAssignment.RoleDefinitionId]){
            #write-output "existing role ht entry############################"
        }
        else{
            #write-output "not existing role ht entry"
            $L0mgmtGroupRoleDefinition = Get-AzRoleDefinition -Id $L0mgmtGroupRoleAssignment.RoleDefinitionId -Scope $L0mgmtGroupRoleAssignment.Scope -verbose
            $htRoles.$($roleId) = @{}
            $htRoles.$($roleId).Id = $($L0mgmtGroupRoleDefinition.Id)
            $htRoles.$($roleId).IsCustom = $($L0mgmtGroupRoleDefinition.IsCustom)
            $htRoles.$($roleId).assignableScopes = $($L0mgmtGroupRoleDefinition.AssignableScopes)
        }  
        $RoleDefinitionId = $L0mgmtGroupRoleAssignment.RoleDefinitionId   
        $RoleDefinitionName = $L0mgmtGroupRoleAssignment.RoleDefinitionName
        $RoleAssignmentDisplayname = $L0mgmtGroupRoleAssignment.DisplayName
        $RoleAssignmentSignInName = $L0mgmtGroupRoleAssignment.SignInName
        $RoleAssignmentObjectId = $L0mgmtGroupRoleAssignment.ObjectId
        $RoleAssignmentObjectType = $L0mgmtGroupRoleAssignment.ObjectType
        $RoleAssignmentId = $L0mgmtGroupRoleAssignment.RoleAssignmentId
        $RoleAssignmentScope = $L0mgmtGroupRoleAssignment.Scope
        $RoleIsCustom = $htRoles.$($roleId).IsCustom
        $RoleAssignableScopes = [string]$htRoles.$($roleId).assignableScopes
        row -l $l -mgName $getMg.DisplayName -mgId $getMg.Name -Policy $Policy -PolicyType $PolicyType -PolicyScope $PolicyScope -PolicyVariant $PolicyVariant -RoleDefinitionId $RoleDefinitionId -RoleDefinitionName $RoleDefinitionName -RoleAssignmentDisplayname $RoleAssignmentDisplayname -RoleAssignmentSignInName $RoleAssignmentSignInName -RoleAssignmentObjectId $RoleAssignmentObjectId -RoleAssignmentObjectType $RoleAssignmentObjectType -RoleAssignmentId $RoleAssignmentId -RoleAssignmentScope $RoleAssignmentScope -RoleIsCustom $RoleIsCustom -RoleAssignableScopes $RoleAssignableScopes
        Clear-Variable -Name "RoleDefinitionId"
        Clear-Variable -Name "RoleDefinitionName"
        Clear-Variable -Name "RoleIsCustom"
        Clear-Variable -Name "RoleAssignmentDisplayname"
        Clear-Variable -Name "RoleAssignmentSignInName"
        Clear-Variable -Name "RoleAssignmentObjectId"
        Clear-Variable -Name "RoleAssignmentObjectType"
        Clear-Variable -Name "RoleAssignmentScope"
        Clear-Variable -Name "RoleAssignableScopes"
    }

    Write-Output "L$l MG Name:'$($getMg.DisplayName)' ID:'$($getMg.Name)' child items: $($getMg.children.count) (MG or Sub)"

    if ($getMg.children.count -gt 0) {
        foreach ($childMg in $getMg.Children | Where-Object { $_.Type -eq "/subscriptions" }) {
            Write-Output "Processing SUB Name:'$($childMg.DisplayName) ID:'$($childMg.Id)''"
            $L1mgmtGroupSubPolicyAssignments = Get-AzPolicyAssignment -Scope "$($childMg.Id)"
            Write-Output "SUB Policy Assignments: $($L1mgmtGroupSubPolicyAssignments.count)"
            foreach ($L1mgmtGroupSubPolicyAssignment in $L1mgmtGroupSubPolicyAssignments) {
                #Write-Output "++++++++++++++++++++++++++++++++++++++++++++++++"
                #$htpolicies
                #Write-Output "++++++++++++++++++++++++++++++++++++++++++++++++"
                #Write-Output "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                #$htpolicySets
                #Write-Output "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                if ($L1mgmtGroupSubPolicyAssignment.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/" -OR $L1mgmtGroupSubPolicyAssignment.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policySetDefinitions/") {
                    $policyId = ($L1mgmtGroupSubPolicyAssignment.properties.policydefinitionid -replace '.*/')
                    #Write-Output "PolicyId = $policyId"
                    if ($L1mgmtGroupSubPolicyAssignment.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/") {
                        $PolicyVariant = "Policy"
                        if ($htPolicies[$policyId]){
                            #write-output "existing ht policy entry############################"
                        }
                        else{
                            #write-output "not existing ht policy entry"
                            $L1mgmtGroupSubPolicyDef = Get-AzPolicydefinition -Id $L1mgmtGroupSubPolicyAssignment.properties.policydefinitionid
                            $htPolicies.$($policyId) = @{}
                            $htPolicies.$($policyId).Id = $($L1mgmtGroupSubPolicyDef.name)
                            $htPolicies.$($policyId).DisplayName = $($L1mgmtGroupSubPolicyDef.Properties.displayname)  
                            $htPolicies.$($policyId).Type = $($L1mgmtGroupSubPolicyDef.Properties.policyType)  
                        }
                        $Policy = $htPolicies[$policyId].DisplayName
                        $PolicyType = $htPolicies[$policyId].Type
                        $PolicyScope = $L1mgmtGroupSubPolicyAssignment.Properties.Scope
                        row -l $l -mgName $getMg.DisplayName -mgId $getMg.Name -subName $childMg.DisplayName -subId $childMg.Id -Policy $Policy -PolicyType $PolicyType -PolicyScope $PolicyScope -PolicyVariant $PolicyVariant -RoleDefinitionId $RoleDefinitionId -RoleDefinitionName $RoleDefinitionName -RoleAssignmentDisplayname $RoleAssignmentDisplayname -RoleAssignmentSignInName $RoleAssignmentSignInName -RoleAssignmentObjectId $RoleAssignmentObjectId -RoleAssignmentObjectType $RoleAssignmentObjectType -RoleAssignmentScope $RoleAssignmentScope -RoleIsCustom $RoleIsCustom -RoleAssignableScopes $RoleAssignableScopes
                        Clear-Variable -Name "Policy"
                        Clear-Variable -Name "PolicyType"
                        Clear-Variable -Name "PolicyScope"
                        Clear-Variable -Name "PolicyVariant"
                    }
                    if ($L1mgmtGroupSubPolicyAssignment.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policySetDefinitions/") {
                        $PolicyVariant = "PolicySet"
                        if ($htPolicySets[$policyId]){
                            #write-output "existing ht policySet entry############################"
                        }
                        else{
                            #write-output "not existing ht policySet entry"
                            $L1mgmtGroupSubPolicySetDef = Get-AzPolicySetdefinition -Id $L1mgmtGroupSubPolicyAssignment.properties.policydefinitionid
                            $htPolicySets.$($policyId) = @{}
                            $htPolicySets.$($policyId).Id = $($L1mgmtGroupSubPolicySetDef.name)
                            $htPolicySets.$($policyId).DisplayName = $($L1mgmtGroupSubPolicySetDef.Properties.displayname)
                            $htPolicySets.$($policyId).Type = $($L1mgmtGroupSubPolicySetDef.Properties.policyType)  
                        }   
                        $Policy = $htPolicySets[$policyId].DisplayName
                        $PolicyType = $htPolicySets[$policyId].Type
                        $PolicyScope = $L1mgmtGroupSubPolicyAssignment.Properties.Scope
                        row -l $l -mgName $getMg.DisplayName -mgId $getMg.Name -subName $childMg.DisplayName -subId $childMg.Id -Policy $Policy -PolicyType $PolicyType -PolicyScope $PolicyScope -PolicyVariant $PolicyVariant -RoleDefinitionId $RoleDefinitionId -RoleDefinitionName $RoleDefinitionName -RoleAssignmentDisplayname $RoleAssignmentDisplayname -RoleAssignmentSignInName $RoleAssignmentSignInName -RoleAssignmentObjectId $RoleAssignmentObjectId -RoleAssignmentObjectType $RoleAssignmentObjectType -RoleAssignmentScope $RoleAssignmentScope -RoleIsCustom $RoleIsCustom -RoleAssignableScopes $RoleAssignableScopes
                        Clear-Variable -Name "Policy"
                        Clear-Variable -Name "PolicyType"
                        Clear-Variable -Name "PolicyScope"
                        Clear-Variable -Name "PolicyVariant"
                    }
                }

            }
            $L1mgmtGroupSubRoleAssignments = Get-AzRoleAssignment -Scope "$($childMg.Id)"
            Write-Output "SUB Role Assignments: $($L1mgmtGroupSubRoleAssignments.count)"
            foreach ($L1mgmtGroupSubRoleAssignment in $L1mgmtGroupSubRoleAssignments) {
                $roleId = $L1mgmtGroupSubRoleAssignment.RoleDefinitionId
                if ($htRoles[$L1mgmtGroupSubRoleAssignment.RoleDefinitionId]){
                    #write-output "existing role ht entry############################"
                }
                else{
                    #write-output "not existing role ht entry"
                    $L1mgmtGroupSubRoleDefinition = Get-AzRoleDefinition -Id $L1mgmtGroupSubRoleAssignment.RoleDefinitionId -Scope $L1mgmtGroupSubRoleAssignment.Scope
                    $htRoles.$($roleId) = @{}
                    $htRoles.$($roleId).Id = $($L1mgmtGroupSubRoleDefinition.Id)
                    $htRoles.$($roleId).IsCustom = $($L1mgmtGroupSubRoleDefinition.IsCustom)
                    $htRoles.$($roleId).assignableScopes = $($L1mgmtGroupSubRoleDefinition.AssignableScopes)
                }  
                $RoleDefinitionId = $L1mgmtGroupSubRoleAssignment.RoleDefinitionId   
                $RoleDefinitionName = $L1mgmtGroupSubRoleAssignment.RoleDefinitionName
                $RoleAssignmentDisplayname = $L1mgmtGroupSubRoleAssignment.DisplayName
                $RoleAssignmentSignInName = $L1mgmtGroupSubRoleAssignment.SignInName
                $RoleAssignmentObjectId = $L1mgmtGroupSubRoleAssignment.ObjectId
                $RoleAssignmentObjectType = $L1mgmtGroupSubRoleAssignment.ObjectType
                $RoleAssignmentId = $L1mgmtGroupSubRoleAssignment.RoleAssignmentId
                $RoleAssignmentScope = $L1mgmtGroupSubRoleAssignment.Scope
                $RoleIsCustom = $htRoles.$($roleId).IsCustom
                $RoleAssignableScopes = [string]$htRoles.$($roleId).assignableScopes
                row -l $l -mgName $getMg.DisplayName -mgId $getMg.Name -subName $childMg.DisplayName -subId $childMg.Id -Policy $Policy -PolicyType $PolicyType -PolicyScope $PolicyScope -RoleDefinitionId $RoleDefinitionId -RoleDefinitionName $RoleDefinitionName -RoleAssignmentDisplayname $RoleAssignmentDisplayname -RoleAssignmentSignInName $RoleAssignmentSignInName -RoleAssignmentObjectId $RoleAssignmentObjectId -RoleAssignmentObjectType $RoleAssignmentObjectType -RoleAssignmentId $RoleAssignmentId -RoleAssignmentScope $RoleAssignmentScope -RoleIsCustom $RoleIsCustom -RoleAssignableScopes $RoleAssignableScopes
                Clear-Variable -Name "RoleDefinitionId"
                Clear-Variable -Name "RoleDefinitionName"
                Clear-Variable -Name "RoleAssignmentDisplayname"
                Clear-Variable -Name "RoleAssignmentSignInName"
                Clear-Variable -Name "RoleAssignmentObjectId"
                Clear-Variable -Name "RoleAssignmentObjectType"
                Clear-Variable -Name "RoleAssignmentScope"
                Clear-Variable -Name "RoleIsCustom"
                Clear-Variable -Name "RoleAssignableScopes"
            }
        }
        foreach ($childMg in $getMg.Children | Where-Object { $_.Type -eq "/providers/Microsoft.Management/managementGroups" }) {
            Write-Output "Trigger Report for: MG-Name:'$($childMg.DisplayName)' MG-ID:'$($childMg.Name)'"
            mgfunc -mgId $childMg.Name -l $l
        }
    }
}
mgfunc -mgId $ManagementGroupRootId -l 0
$table | Export-Csv -Path "$csvPath\MG-Report_$ManagementGroupRootId`_$csvFileTimestamp.csv" -Delimiter "," -NoTypeInformation