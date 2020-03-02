<#notes
Role assignments to Unknown Object happens when the graph object(User/Group/Service principal) gets deleted from the directory after the Role assignment was created.
Since the graph entity is deleted, we cannot figure out the object's displayname or type from graph, due to which we show the objecType as Unknown.
#>

#Requires -Modules @{ ModuleName="Az.Resources"; ModuleVersion="1.9.1" }

Param
(
    #enter your tenantId #(Get-AzContext).Tenant.Id
    [Parameter(Mandatory = $False)][string]$managementGroupRootId = "11a5557c-f80f-4925-9d04-c05ecd061ffa",
    #CSV file delimiter use either semicolon or comma 
    [Parameter(Mandatory = $False)][string]$csvDelimiter = ";"
)


#helper for file naming
$fileTimestamp = (get-date -format "yyyyMMddHHmmss")

#validate tenantId
if ((Get-AzContext).Tenant.Id -ne $managementGroupRootId) {
    Write-Output "context does not match! you are currently connected to tenantId:'$((Get-AzContext).Tenant.Id)'";break
}

#CODE--------------------------------------------------------------------------------
#create table object
$table = $null
$table = New-Object system.Data.DataTable "MG-Sub-Governance-Report"

#create common columns
$table.columns.add((New-Object system.Data.DataColumn Level, ([string])))
$table.columns.add((New-Object system.Data.DataColumn MgName, ([string])))
$table.columns.add((New-Object system.Data.DataColumn MgId, ([string])))
$table.columns.add((New-Object system.Data.DataColumn mgParentId, ([string])))
$table.columns.add((New-Object system.Data.DataColumn mgParentName, ([string])))
$table.columns.add((New-Object system.Data.DataColumn Subscription, ([string])))
$table.columns.add((New-Object system.Data.DataColumn SubscriptionId, ([string])))
$table.columns.add((New-Object system.Data.DataColumn Policy, ([string])))
$table.columns.add((New-Object system.Data.DataColumn PolicyType, ([string])))
$table.columns.add((New-Object system.Data.DataColumn PolicyDefinitionIdGuid, ([string])))
$table.columns.add((New-Object system.Data.DataColumn PolicyDefinitionIdFull, ([string])))
$table.columns.add((New-Object system.Data.DataColumn PolicyAssignmentScope, ([string])))
$table.columns.add((New-Object system.Data.DataColumn PolicyAssignmentId, ([string])))
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

function row($l, $mgName, $mgId, $mgParentId, $mgParentName, $subName, $subId, $Policy, $PolicyType, $PolicyDefinitionIdFull, $PolicyDefinitionIdGuid, $PolicyAssignmentScope, $PolicyAssignmentId, $PolicyVariant, $RoleDefinitionId, $RoleDefinitionName, $RoleAssignmentDisplayname, $RoleAssignmentSignInName, $RoleAssignmentObjectId, $RoleAssignmentObjectType, $RoleAssignmentId, $RoleAssignmentScope, $RoleIsCustom, $RoleAssignableScopes) {
    $row = $table.NewRow()
    $row.Level = $l
    $row.MgName = $mgName
    $row.MgId = $mgId
    $row.mgParentId = $mgParentId
    $row.mgParentName = $mgParentName
    $row.Subscription = $subName
    $row.SubscriptionId = $subId
    $row.Policy = $Policy
    $row.PolicyType = $PolicyType
    $row.PolicyDefinitionIdFull = $PolicyDefinitionIdFull
    $row.PolicyDefinitionIdGuid = $PolicyDefinitionIdGuid
    $row.PolicyAssignmentScope = $PolicyAssignmentScope
    $row.PolicyAssignmentId = $PolicyAssignmentId
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
function mgfunc($mgId, $l, $mgParentId, $mgParentName) {
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
            if ($L0mgmtGroupPolicyAssignment.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/") {
                #policy
                $PolicyVariant = "Policy"
                if ($L0mgmtGroupPolicyAssignment.properties.policydefinitionid -match "/providers/Microsoft.Management/managementGroups/") {
                    #custom policy
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
                        $htPolicies.$($policyId).PolicyDefinitionId = $($L0mgmtGroupPolicyDef.PolicyDefinitionId)
                    }   
                }
                else {
                    #built-in policy
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
                        $htPolicies.$($policyId).PolicyDefinitionId = $($L0mgmtGroupPolicyDef.PolicyDefinitionId)
                    }
                }
                $Policy = $htPolicies[$policyId].DisplayName
                $PolicyType = $htPolicies[$policyId].Type
                $PolicyDefinitionIdFull = $htPolicies[$policyId].PolicyDefinitionId
                $PolicyDefinitionIdGuid = $htPolicies[$policyId].Id
                $PolicyAssignmentScope = $L0mgmtGroupPolicyAssignment.Properties.Scope
                $PolicyAssignmentId = $L0mgmtGroupPolicyAssignment.PolicyAssignmentId
                row -l $l -mgName $getMg.DisplayName -mgId $getMg.Name -mgParentId $mgParentId -mgParentName $mgParentName -Policy $Policy -PolicyType $PolicyType -PolicyDefinitionIdFull $PolicyDefinitionIdFull -PolicyDefinitionIdGuid $PolicyDefinitionIdGuid -PolicyAssignmentScope $PolicyAssignmentScope -PolicyAssignmentId $PolicyAssignmentId -PolicyVariant $PolicyVariant -RoleDefinitionId $RoleDefinitionId -RoleDefinitionName $RoleDefinitionName -RoleAssignmentDisplayname $RoleAssignmentDisplayname -RoleAssignmentSignInName $RoleAssignmentSignInName -RoleAssignmentObjectId $RoleAssignmentObjectId -RoleAssignmentObjectType $RoleAssignmentObjectType -RoleAssignmentScope $RoleAssignmentScope -RoleIsCustom $RoleIsCustom -RoleAssignableScopes $RoleAssignableScopes
                Clear-Variable -Name "Policy"
                Clear-Variable -Name "PolicyType"
                Clear-Variable -Name "PolicyDefinitionIdFull"
                Clear-Variable -Name "PolicyDefinitionIdGuid"
                Clear-Variable -Name "PolicyAssignmentScope"
                Clear-Variable -Name "PolicyAssignmentId"
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
                        $htPolicySets.$($policyId).PolicySetDefinitionId = $($L0mgmtGroupPolicySetDef.PolicySetDefinitionId)
                    }   
                }
                else {
                    #built-in policySet
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
                        $htPolicySets.$($policyId).PolicySetDefinitionId = $($L0mgmtGroupPolicySetDef.PolicySetDefinitionId)
                    }   
                }
                $Policy = $htPolicySets[$policyId].DisplayName
                $PolicyType = $htPolicySets[$policyId].Type
                $PolicyDefinitionIdFull = $htPolicySets[$policyId].PolicySetDefinitionId
                $PolicyDefinitionIdGuid = $htPolicySets[$policyId].Id
                $PolicyAssignmentScope = $L0mgmtGroupPolicyAssignment.Properties.Scope
                $PolicyAssignmentId = $L0mgmtGroupPolicyAssignment.PolicyAssignmentId
                row -l $l -mgName $getMg.DisplayName -mgId $getMg.Name -mgParentId $mgParentId -mgParentName $mgParentName -Policy $Policy -PolicyType $PolicyType -PolicyDefinitionIdFull $PolicyDefinitionIdFull -PolicyDefinitionIdGuid $PolicyDefinitionIdGuid -PolicyAssignmentScope $PolicyAssignmentScope -PolicyAssignmentId $PolicyAssignmentId -PolicyVariant $PolicyVariant -RoleDefinitionId $RoleDefinitionId -RoleDefinitionName $RoleDefinitionName -RoleAssignmentDisplayname $RoleAssignmentDisplayname -RoleAssignmentSignInName $RoleAssignmentSignInName -RoleAssignmentObjectId $RoleAssignmentObjectId -RoleAssignmentObjectType $RoleAssignmentObjectType -RoleAssignmentScope $RoleAssignmentScope -RoleIsCustom $RoleIsCustom -RoleAssignableScopes $RoleAssignableScopes
                Clear-Variable -Name "Policy"
                Clear-Variable -Name "PolicyType"
                Clear-Variable -Name "PolicyDefinitionIdFull"
                Clear-Variable -Name "PolicyDefinitionIdGuid"
                Clear-Variable -Name "PolicyAssignmentScope"
                Clear-Variable -Name "PolicyAssignmentId"
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
        #$htRoles
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
        row -l $l -mgName $getMg.DisplayName -mgId $getMg.Name -mgParentId $mgParentId -mgParentName $mgParentName -Policy $Policy -PolicyType $PolicyType -PolicyDefinitionIdFull $PolicyDefinitionIdFull -PolicyDefinitionIdGuid $PolicyDefinitionIdGuid -PolicyAssignmentScope $PolicyAssignmentScope -PolicyAssignmentId $PolicyAssignmentId -PolicyVariant $PolicyVariant -RoleDefinitionId $RoleDefinitionId -RoleDefinitionName $RoleDefinitionName -RoleAssignmentDisplayname $RoleAssignmentDisplayname -RoleAssignmentSignInName $RoleAssignmentSignInName -RoleAssignmentObjectId $RoleAssignmentObjectId -RoleAssignmentObjectType $RoleAssignmentObjectType -RoleAssignmentId $RoleAssignmentId -RoleAssignmentScope $RoleAssignmentScope -RoleIsCustom $RoleIsCustom -RoleAssignableScopes $RoleAssignableScopes
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
                #$htpolicies
                #$htpolicySets
                if ($L1mgmtGroupSubPolicyAssignment.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/" -OR $L1mgmtGroupSubPolicyAssignment.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policySetDefinitions/") {
                    $policyId = ($L1mgmtGroupSubPolicyAssignment.properties.policydefinitionid -replace '.*/')
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
                            $htPolicies.$($policyId).PolicyDefinitionId = $($L1mgmtGroupSubPolicyDef.PolicyDefinitionId)
                        }
                        $Policy = $htPolicies[$policyId].DisplayName
                        $PolicyType = $htPolicies[$policyId].Type
                        $PolicyDefinitionIdFull = $htPolicies[$policyId].PolicyDefinitionId
                        $PolicyDefinitionIdGuid = $htPolicies[$policyId].Id
                        $PolicyAssignmentScope = $L1mgmtGroupSubPolicyAssignment.Properties.Scope
                        $PolicyAssignmentId = $L1mgmtGroupSubPolicyAssignment.PolicyAssignmentId
                        row -l $l -mgName $getMg.DisplayName -mgId $getMg.Name -mgParentId $mgParentId -mgParentName $mgParentName -subName $childMg.DisplayName -subId $childMg.Id -Policy $Policy -PolicyType $PolicyType -PolicyDefinitionIdFull $PolicyDefinitionIdFull -PolicyDefinitionIdGuid $PolicyDefinitionIdGuid -PolicyAssignmentScope $PolicyAssignmentScope -PolicyAssignmentId $PolicyAssignmentId -PolicyVariant $PolicyVariant -RoleDefinitionId $RoleDefinitionId -RoleDefinitionName $RoleDefinitionName -RoleAssignmentDisplayname $RoleAssignmentDisplayname -RoleAssignmentSignInName $RoleAssignmentSignInName -RoleAssignmentObjectId $RoleAssignmentObjectId -RoleAssignmentObjectType $RoleAssignmentObjectType -RoleAssignmentScope $RoleAssignmentScope -RoleIsCustom $RoleIsCustom -RoleAssignableScopes $RoleAssignableScopes
                        Clear-Variable -Name "Policy"
                        Clear-Variable -Name "PolicyType"
                        Clear-Variable -Name "PolicyDefinitionIdFull"
                        Clear-Variable -Name "PolicyDefinitionIdGuid"
                        Clear-Variable -Name "PolicyAssignmentScope"
                        Clear-Variable -Name "PolicyAssignmentId"
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
                            $htPolicySets.$($policyId).PolicySetDefinitionId = $($L1mgmtGroupSubPolicySetDef.PolicySetDefinitionId) 
                            
                        }   
                        $Policy = $htPolicySets[$policyId].DisplayName
                        $PolicyType = $htPolicySets[$policyId].Type
                        $PolicyDefinitionIdFull = $htPolicySets[$policyId].PolicySetDefinitionId
                        $PolicyDefinitionIdGuid = $htPolicySets[$policyId].Id
                        $PolicyAssignmentScope = $L1mgmtGroupSubPolicyAssignment.Properties.Scope
                        $PolicyAssignmentId = $L1mgmtGroupSubPolicyAssignment.PolicyAssignmentId
                        row -l $l -mgName $getMg.DisplayName -mgId $getMg.Name -mgParentId $mgParentId -mgParentName $mgParentName -subName $childMg.DisplayName -subId $childMg.Id -Policy $Policy -PolicyType $PolicyType -PolicyDefinitionIdFull $PolicyDefinitionIdFull -PolicyDefinitionIdGuid $PolicyDefinitionIdGuid -PolicyAssignmentScope $PolicyAssignmentScope -PolicyAssignmentId $PolicyAssignmentId -PolicyVariant $PolicyVariant -RoleDefinitionId $RoleDefinitionId -RoleDefinitionName $RoleDefinitionName -RoleAssignmentDisplayname $RoleAssignmentDisplayname -RoleAssignmentSignInName $RoleAssignmentSignInName -RoleAssignmentObjectId $RoleAssignmentObjectId -RoleAssignmentObjectType $RoleAssignmentObjectType -RoleAssignmentScope $RoleAssignmentScope -RoleIsCustom $RoleIsCustom -RoleAssignableScopes $RoleAssignableScopes
                        Clear-Variable -Name "Policy"
                        Clear-Variable -Name "PolicyType"
                        Clear-Variable -Name "PolicyDefinitionIdFull"
                        Clear-Variable -Name "PolicyDefinitionIdGuid"
                        Clear-Variable -Name "PolicyAssignmentScope"
                        Clear-Variable -Name "PolicyAssignmentId"
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
                row -l $l -mgName $getMg.DisplayName -mgId $getMg.Name -mgParentId $mgParentId -mgParentName $mgParentName -subName $childMg.DisplayName -subId $childMg.Id -Policy $Policy -PolicyType $PolicyType -PolicyDefinitionIdFull $PolicyDefinitionIdFull -PolicyDefinitionIdGuid $PolicyDefinitionIdGuid -PolicyAssignmentScope $PolicyAssignmentScope -PolicyAssignmentId $PolicyAssignmentId -RoleDefinitionId $RoleDefinitionId -RoleDefinitionName $RoleDefinitionName -RoleAssignmentDisplayname $RoleAssignmentDisplayname -RoleAssignmentSignInName $RoleAssignmentSignInName -RoleAssignmentObjectId $RoleAssignmentObjectId -RoleAssignmentObjectType $RoleAssignmentObjectType -RoleAssignmentId $RoleAssignmentId -RoleAssignmentScope $RoleAssignmentScope -RoleIsCustom $RoleIsCustom -RoleAssignableScopes $RoleAssignableScopes
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
            mgfunc -mgId $childMg.Name -l $l -mgParentId $getMg.Name -mgParentName $getMg.DisplayName
        }
    }
}

#Build hierachy
function subForMgFunc($mgChild) {
#sub
    write-output "checking for Subs for $mgChild"
    $subscriptions = ($table | Where-Object { "" -ne $_.Subscription -and $_.mgId -eq $mgChild }).SubscriptionId | Get-Unique
    if ($subscriptions.Count -gt 0){
        foreach ($subscriptionId in $subscriptions){
            $subscription = ($table | Where-Object { "$subscriptionId" -eq $_.SubscriptionId -and $_.mgId -eq $mgChild }).Subscription | Get-Unique
            write-output "subscription: $subscription"
        }
$script:html += @"
                    <li><a class="aSub" href="#$mgChild"><p id="hierachySub_$mgChild">$($subscriptions.Count)x<br>Subscription</p></a></li>
"@
$script:markdown += @"
 $mgChild[$mgChild] --> Subsof$mgChild[Subs: $($subscriptions.Count)]`r`n
"@
$script:arraySubs += "Subsof$mgChild"
    }
}

function subForMgUlFunc($mgChild) {
    write-output "checking for Subs for $mgChild"
    $subscriptions = ($table | Where-Object { "" -ne $_.Subscription -and $_.mgId -eq $mgChild }).SubscriptionId | Get-Unique
    if ($subscriptions.Count -gt 0){
$script:html += @"
                <ul>
"@
        foreach ($subscriptionId in $subscriptions){
            $subscription = ($table | Where-Object { "$subscriptionId" -eq $_.SubscriptionId -and $_.mgId -eq $mgChild }).Subscription | Get-Unique
            write-output "subscription: $subscription"
$script:html += @"
        
"@
        }
$script:html += @"
                    <li><a class="aSub" href="#$mgChild"><p id="hierachySub_$mgChild">$($subscriptions.Count)x<br>Subscription</p></a></li></ul>
"@
$script:markdown += @"
 $mgChild[$mgChild] --> Subsof$mgChild[Subs: $($subscriptions.Count)]`r`n
"@
$script:arraySubs += "Subsof$mgChild"
    }
}

function mgHierachyFunc($mgChild) {

    write-output "processingInFunction: $mgChild"
    #$subscriptions = ($table | Where-Object { "" -ne $_.Subscription -and $_.mgId -eq $mgChild }).Subscription | Get-Unique
    $mgName = ($table | Where-Object {$_.mgId -eq "$mgChild"}).mgName | Get-Unique
$script:html += @"
                    <li><a class="aMg" href="#$mgChild"><p id="hierachy_$mgChild">$mgName<br><i>$mgChild</i></p></a>
"@
    write-output "checking for childMgs for $mgChild"
    $childMgs = ($table | Where-Object {$_.mgParentId -eq "$mgChild"}).mgId | Get-Unique
    if ($childMgs.count -gt 0){
$script:html += @"
                <ul>
"@
        foreach ($childMg in $childMgs){
            write-output "processingFMg: $childMg"
            mgHierachyFunc -mgChild $childMg

$script:markdown += @"
 $mgChild[$mgChild] --> $childMg[$childMg]`r`n
"@
$script:arrayMgs += "$childMg"

        }
        subForMgFunc -mgChild $mgChild
$script:html += @"
                </ul>
            </li>    
"@
    }
    else{
        write-output "processingF: no childMgs for $mgChild"
        subForMgUlFunc -mgChild $mgChild

$script:html += @"
            </li>
"@
    }
}

function mgSubDetailsTable($mgOrSub, $policiesCount, $policiesAssigned, $policySetsCount, $policySetsAssigned, $policiesInherited, $policySetsInherited, $scopePolicies, $scopePoliciesCount, $scopePolicySets, $scopePolicySetsCount, $rolesAssigned, $rolesAssignedCount, $rolesAssignedInherited){

if ($mgOrSub -eq "mg"){
    $cssClass = "mgDetailsTable"
}
if ($mgOrSub -eq "sub"){
    $cssClass = "subDetailsTable"
}

if ($policiesCount -gt 0){

$script:html += @"
    <button type="button" class="collapsible"><p><i class="fa fa-plus" aria-hidden="true"></i> $policiesCount Policy Assignment(s) ($policiesInherited inherited)</p></button>
    <div class="content">
        <table class="$cssClass">
            <tr>
                <th class="widthCustom">
                    Policy DisplayName
                </th>
                <th>
                    Type
                </th>
                <th>
                    Inheritance
                </th>
            </tr>
"@
            foreach ($policyAssignment in $policiesAssigned){
                if ($policyAssignment.policyType -eq "builtin"){
                    $policyWithWithoutLinkToAzAdvertizer = "<a href=`"https://www.azadvertizer.net/azpolicyadvertizer/$($policyAssignment.policyDefinitionIdGuid).html`" target=`"_blank`"><i class=`"fa fa-link`" aria-hidden=`"true`"></i> $($policyAssignment.policy)</a>"
                }
                else{
                    $policyWithWithoutLinkToAzAdvertizer = $policyAssignment.policy
                }
$script:html += @"
            <tr>
                <td>
                    $policyWithWithoutLinkToAzAdvertizer
                </td>
                <td>
                    $($policyAssignment.policyType)
                </td>
                <td>
                    $($policyAssignment.PolicyAssignmentId)
                </td>
            </tr>
"@        
            }
$script:html += @"
        </table>
    </div>
"@
        }
        else{
$script:html += @"
            <p><i class="fa fa-minus" aria-hidden="true"></i> $policiesCount Policy Assignment(s) ($policiesInherited inherited)</p>
"@
        }
$script:html += @"
        </td></tr>
        <tr><td>
"@
        if ($policySetsCount -gt 0){
    
$script:html += @"
    <button type="button" class="collapsible"><p><i class="fa fa-plus" aria-hidden="true"></i> $policySetsCount PolicySet Assignment(s) ($policySetsInherited inherited)</p></button>
    <div class="content">
        <table class="$cssClass">
            <tr>
                <th class="widthCustom">
                    PolicySet DisplayName
                </th>
                <th>
                    Type
                </th>
                <th>
                    Inheritance
                </th>
            </tr>
"@
            foreach ($policySetAssignment in $policySetsAssigned){
                if ($policySetAssignment.policyType -eq "builtin"){
                    $policyWithWithoutLinkToAzAdvertizer = "<a href=`"https://www.azadvertizer.net/azpolicyinitiativesadvertizer/$($policySetAssignment.policyDefinitionIdGuid).html`" target=`"_blank`"><i class=`"fa fa-link`" aria-hidden=`"true`"></i> $($policySetAssignment.policy)</a>"
                }
                else{
                    $policyWithWithoutLinkToAzAdvertizer = $policySetAssignment.policy
                }
$script:html += @"
            <tr>
                <td>
                    $policyWithWithoutLinkToAzAdvertizer
                </td>
                <td>
                    $($policySetAssignment.policyType)
                </td>
                <td>
                    $($policySetAssignment.PolicyAssignmentId)
                </td>
            </tr>
"@        
            }
$script:html += @"
        </table>
    </div>
"@
        }
        else{
$script:html += @"
            <p><i class="fa fa-minus" aria-hidden="true"></i> $policySetsCount PolicySet Assignment(s) ($policySetsInherited inherited)</p>
"@
        }
$script:html += @"
        </td></tr>
        <tr><td>
"@
    
    if ($scopePoliciesCount -gt 0){
    
$script:html += @"
        <button type="button" class="collapsible"><p><i class="fa fa-plus" aria-hidden="true"></i> $scopePoliciesCount Policies (custom) scoped (where an assignment exists)</p></button>
        <div class="content">
            <table class="$cssClass">
                <tr>
                    <th class="widthCustom">
                        Policy DisplayName
                    </th>
                    <th>
                        PolicyDefinitionId
                    </th>
                </tr>
"@
                foreach ($scopePolicy in $scopePolicies){
        
$script:html += @"
                <tr>
                    <td>
                        $($scopePolicy.policy)
                    </td>
                    <td>
                        $($scopePolicy.PolicyDefinitionIdFull)
                    </td>
                </tr>
"@        
                }
$script:html += @"
            </table>
        </div>
"@
            }
            else{
$script:html += @"
                    <p><i class="fa fa-minus" aria-hidden="true"></i> $scopePoliciesCount Policies (custom) scoped (where an assignment exists)</p>
"@
            }
$script:html += @"
                </td></tr>
                <tr><td>
"@
    
    if ($scopePolicySetsCount -gt 0){
    
$script:html += @"
        <button type="button" class="collapsible"><p><i class="fa fa-plus" aria-hidden="true"></i> $scopePolicySetsCount PolicySets/Initiatives (custom) scoped (where an assignment exists)</p></button>
        <div class="content">
            <table class="$cssClass">
                <tr>
                    <th class="widthCustom">
                        PolicySet DisplayName
                    </th>
                    <th>
                        PolicySetDefinitionId
                    </th>
                </tr>
"@
                foreach ($scopePolicySet in $scopePolicySets){
        
$script:html += @"
                <tr>
                    <td>
                        $($scopePolicySet.policy)
                    </td>
                    <td>
                        $($scopePolicySet.PolicyDefinitionIdFull)
                    </td>
                </tr>
"@        
                }
$script:html += @"
            </table>
        </div>
"@
            }
            else{
$script:html += @"
                    <p><i class="fa fa-minus" aria-hidden="true"></i> $scopePolicySetsCount PolicySets/Initiatives (custom) scoped (where an assignment exists)</p>
"@
            }
$script:html += @"
                </td></tr>
                <tr><td>
"@
    
    if ($rolesAssignedCount -gt 0){
    
$script:html += @"
        <button type="button" class="collapsible"><p><i class="fa fa-plus" aria-hidden="true"></i> $rolesAssignedCount Role Assignment(s) ($rolesAssignedInherited inherited)</p></button>
        <div class="content">
            <table class="$cssClass">
                <tr>
                    <th class="widthCustom">
                        Role DisplayName
                    </th>
                    <th>
                        Role Type
                    </th>
                    <th>
                        Obj Type
                    </th>
                    <th>
                        Obj DisplayName
                    </th>
                    <th>
                        Role Assignment
                    </th>
                </tr>
"@
                foreach ($roleAssigned in $rolesAssigned){
                    if ($roleAssigned.RoleIsCustom -eq "FALSE"){
                        $roleType = "Builtin"
                        #$roleWithWithoutLinkToAzAdvertizer = "<a href=`"https://www.azadvertizer.net/azpolicyinitiativesadvertizer/$($policySetAssignment.policyDefinitionIdGuid).html`" target=`"_blank`">$($policySetAssignment.policy)</a>"
                        $roleWithWithoutLinkToAzAdvertizer = "<a href=`"https://www.azadvertizer.net/azrolesadvertizer_all.html`" target=`"_blank`"><i class=`"fa fa-link`" aria-hidden=`"true`"></i> $($roleAssigned.RoleDefinitionName)</a>"
                        #$roleWithWithoutLinkToAzAdvertizer = $roleAssigned.RoleDefinitionName
                    }
                    else{
                        $roleType = "Custom"
                        $roleWithWithoutLinkToAzAdvertizer = $roleAssigned.RoleDefinitionName
                    }
$script:html += @"
                <tr>
                    <td>
                        $roleWithWithoutLinkToAzAdvertizer
                    </td>
                    <td>
                        $roleType
                    </td>
                    <td>
                        $($roleAssigned.RoleAssignmentObjectType)
                    </td>
                    <td>
                        $($roleAssigned.RoleAssignmentDisplayname)
                    </td>
                    <td>
                        $($roleAssigned.RoleAssignmentId)
                    </td>
                </tr>
"@        
                }
$script:html += @"
            </table>
        </div>
"@
            }
            else{
$script:html += @"
                <p><i class="fa fa-minus" aria-hidden="true"></i> $rolesAssignedCount Role Assignment(s) ($rolesAssignedInherited inherited)</p>
"@
            }
$script:html += @"
                </td></tr>
                <tr><td>
"@
}

function subForMgTextFunc($mgChild) {
    write-output "checking for Subs for $mgChild"
    $subscriptions = ($table | Where-Object { "" -ne $_.Subscription -and $_.mgId -eq $mgChild }).SubscriptionId | Get-Unique
    if ($subscriptions.Count -gt 0){
$script:html += @"
            <p><i class="fa fa-info-circle" aria-hidden="true"></i> $($subscriptions.Count) Subscription(s) linked</p>
        </td>
    </tr>
    <tr>
        <td>
            <table class="subTable">
"@
        foreach ($subscriptionId in $subscriptions){
            $subscription = ($table | Where-Object { "$subscriptionId" -eq $_.SubscriptionId -and $_.mgId -eq $mgChild }).Subscription | Get-Unique
            write-output "subscriptionId: $subscriptionId"
            #POLICY
            $policyReleatedQuery = $table | Where-Object { $_.SubscriptionId -eq "$subscriptionId" -and "" -ne $_.Policy}
            $policiesCount = ($policyReleatedQuery | where-object {$_.PolicyVariant -eq "Policy"}).count
            $policiesAssigned = $policyReleatedQuery | where-object {$_.PolicyVariant -eq "Policy"} | Sort-Object -Property Policy, PolicyType
            $policySetsCount = ($policyReleatedQuery | where-object {$_.PolicyVariant -eq "PolicySet"}).count
            $policySetsAssigned = $policyReleatedQuery | where-object {$_.PolicyVariant -eq "PolicySet"} | Sort-Object -Property Policy, PolicyType
            $policiesInherited = ($policyReleatedQuery | where-object {$_.PolicyVariant -eq "Policy" -and $_.PolicyAssignmentId -notmatch "$subscriptionId/"}).count
            $policySetsInherited = ($policyReleatedQuery | where-object {$_.PolicyVariant -eq "PolicySet" -and $_.PolicyAssignmentId -notmatch "$subscriptionId/"}).count
            $scopePolicies = (($policyReleatedQuery| Where-Object { $_.PolicyVariant -eq "Policy" -and $_.PolicyDefinitionIdFull -match "$subscriptionId/" }))
            $scopePoliciesCount = (($policyReleatedQuery| Where-Object { $_.PolicyVariant -eq "Policy" -and $_.PolicyDefinitionIdFull -match "$subscriptionId/" }).PolicyDefinitionIdFull | sort-object -Unique ).count
            $scopePolicySets = (($policyReleatedQuery| Where-Object { $_.PolicyVariant -eq "PolicySet" -and $_.PolicyDefinitionIdFull -match "$subscriptionId/" }))
            $scopePolicySetsCount = (($policyReleatedQuery| Where-Object { $_.PolicyVariant -eq "PolicySet" -and $_.PolicyDefinitionIdFull -match "$subscriptionId/" }).PolicyDefinitionIdFull | sort-object -Unique ).count
            #RBAC
            $rbacReleatedQuery = $table | Where-Object { $_.SubscriptionId -eq "$subscriptionId" -and "" -ne $_.RoleDefinitionName }
            $rolesAssigned = $rbacReleatedQuery
            $rolesAssignedCount = $rbacReleatedQuery.count
            $rolesAssignedInherited = ($rbacReleatedQuery | Where-Object { $_.RoleAssignmentId -notmatch "$subscriptionId/" }).count
$script:html += @"
    <tr>
        <th>
            <p><span id="$subscriptionId"><b>$subscription</b> (Id: <i>$($subscriptionId -replace '.*/')</i>)</span></p>
        </th>
    </tr>
    <tr>
        <td>
            <p><a href="#hierachySub_$mgChild"><i class="fa fa-eye" aria-hidden="true"></i> <i>Highlight Sub in hierachy</i></a></p>
        </td>
    </tr>
    <tr>
        <td>
"@

mgSubDetailsTable -mgOrSub "sub" -policiesCount $policiesCount -policiesAssigned $policiesAssigned -policySetsCount $policySetsCount -policySetsAssigned $policySetsAssigned -policiesInherited $policiesInherited -policySetsInherited $policySetsInherited -scopePolicies $scopePolicies -scopePoliciesCount $scopePoliciesCount -scopePolicySets $scopePolicySets -scopePolicySetsCount $scopePolicySetsCount -rolesAssigned $rolesAssigned -rolesAssignedCount $rolesAssignedCount -rolesAssignedInherited $rolesAssignedInherited

        }
    }
    else{
$script:html += @"

            <p><i class="fa fa-info-circle" aria-hidden="true"></i> $($subscriptions.Count) Subscription(s) linked</p>

"@  
    }
$script:html += @"
                    </td>
                </tr>
            </table>
        </td>
    </tr>
</table>
"@
}
function mgHierachyTextFunc($mgChild, $mgChildOf) {
    write-output "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    write-output "processingInFunction: $mgChild"
    $mgName = ($table | Where-Object {$_.mgId -eq "$mgChild"}).mgName | Get-Unique
    $mgChildOfName = ($table | Where-Object {$_.mgId -eq "$mgChildOf"}).mgName | Get-Unique
    #POLICY
    $policyReleatedQuery = $table | Where-Object { $_.mgId -eq $mgChild -and "" -ne $_.Policy -and "" -eq $_.Subscription}
    $policiesCount = ($policyReleatedQuery | where-object {$_.PolicyVariant -eq "Policy"}).count
    $policiesAssigned = $policyReleatedQuery | where-object {$_.PolicyVariant -eq "Policy"} | Sort-Object -Property Policy, PolicyType
    $policySetsCount = ($policyReleatedQuery | where-object {$_.PolicyVariant -eq "PolicySet"}).count
    $policySetsAssigned = $policyReleatedQuery | where-object {$_.PolicyVariant -eq "PolicySet"} | Sort-Object -Property Policy, PolicyType
    $policiesInherited = ($policyReleatedQuery | where-object {$_.PolicyVariant -eq "Policy" -and $_.PolicyAssignmentId -notmatch "/providers/Microsoft.Management/managementGroups/$mgChild/"}).count
    $policySetsInherited = ($policyReleatedQuery | where-object {$_.PolicyVariant -eq "PolicySet" -and $_.PolicyAssignmentId -notmatch "/providers/Microsoft.Management/managementGroups/$mgChild/"}).count
    $scopePolicies = (($policyReleatedQuery| Where-Object { $_.PolicyVariant -eq "Policy" -and $_.PolicyDefinitionIdFull -match "/providers/Microsoft.Management/managementGroups/$mgChild/" }))
    $scopePoliciesCount = (($policyReleatedQuery| Where-Object { $_.PolicyVariant -eq "Policy" -and $_.PolicyDefinitionIdFull -match "/providers/Microsoft.Management/managementGroups/$mgChild/" }).PolicyDefinitionIdFull | sort-object -Unique ).count
    $scopePolicySets = (($policyReleatedQuery| Where-Object { $_.PolicyVariant -eq "PolicySet" -and $_.PolicyDefinitionIdFull -match "/providers/Microsoft.Management/managementGroups/$mgChild/" }))
    $scopePolicySetsCount = (($policyReleatedQuery| Where-Object { $_.PolicyVariant -eq "PolicySet" -and $_.PolicyDefinitionIdFull -match "/providers/Microsoft.Management/managementGroups/$mgChild/" }).PolicyDefinitionIdFull | sort-object -Unique ).count
    #RBAC
    $rbacReleatedQuery = $table | Where-Object { $_.mgId -eq $mgChild -and "" -eq $_.Subscription -and "" -ne $_.RoleDefinitionName }
    $rolesAssigned = $rbacReleatedQuery
    $rolesAssignedCount = $rbacReleatedQuery.count
    $rolesAssignedInherited = ($rbacReleatedQuery | Where-Object { $_.RoleAssignmentId -notmatch "/providers/Microsoft.Management/managementGroups/$mgChild/" }).count
$script:html += @"
    <br>
    <table id="$mgChild">
        <tr>
            <th class="mg">
                <span><b>$mgName</b> (Id: <i>$mgChild</i>)</span>
            </th>
        </tr>
        <tr>
            <td>
                <p><a href="#hierachy_$mgChild"><i class="fa fa-eye" aria-hidden="true"></i> <i>Highlight MG in hierachy</i></a></p>
            </td>
        </tr>
        <tr>
            <td>
                <p>Child of '$mgChildOfName' (Id: <i>$mgChildOf</i>)</p>
            </td>
        </tr>
        <tr>
            <td>
"@
    write-output "creating mgDetailsTable content"    
    mgSubDetailsTable -mgOrSub "mg" -policiesCount $policiesCount -policiesAssigned $policiesAssigned -policySetsCount $policySetsCount -policySetsAssigned $policySetsAssigned -policiesInherited $policiesInherited -policySetsInherited $policySetsInherited -scopePolicies $scopePolicies -scopePoliciesCount $scopePoliciesCount -scopePolicySets $scopePolicySets -scopePolicySetsCount $scopePolicySetsCount -rolesAssigned $rolesAssigned -rolesAssignedCount $rolesAssignedCount -rolesAssignedInherited $rolesAssignedInherited
    write-output "checking for subs for $mgChild"
    subForMgTextFunc -mgChild $mgChild
    $childMgs = ($table | Where-Object {$_.mgParentId -eq "$mgChild"}).mgId | sort-object -Unique
    if ($childMgs.count -gt 0){
        foreach ($childMg in $childMgs){
            write-output "checking for childmgs for $mgChild"
            mgHierachyTextFunc -mgChild $childMg -mgChildOf $mgChild
        }
    }
    else{
        write-output "no childMgs for $mgChild"
    }
}

###########FUNCTIONS END

#Build the Array, CSV
mgfunc -mgId $managementGroupRootId -l 0 -mgParentId "Tenant" -mgParentName "Tenant"
$table | Export-Csv "mg-sub-hierachy_$managementGroupRootId`_$fileTimestamp.csv" -Delimiter "$csvDelimiter" -NoTypeInformation

#Build the hierachy
$arrayMgs = @()
$stringMgs =""
$arraySubs = @()
$stringSubs =""
$html = $null
$markdown = $null
$html += @"
<!doctype html>
<html lang="en">
<html style="height: 100%">
<head>
    <meta charset="utf-8" />
    <link rel="stylesheet" type="text/css" href="https://www.azadvertizer.net/azure-mg-sub-governance-reporting/hierachy.css">
    <!--<link rel="stylesheet" type="text/css" href="hierachy.css">-->
    <script src="https://code.jquery.com/jquery-1.7.2.js" integrity="sha256-FxfqH96M63WENBok78hchTCDxmChGFlo+/lFIPcZPeI=" crossorigin="anonymous"></script>
    <script src="https://code.jquery.com/ui/1.8.18/jquery-ui.js" integrity="sha256-lzf/CwLt49jbVoZoFcPZOc0LlMYPFBorVSwMsTs2zsA=" crossorigin="anonymous"></script>
    <script type="text/javascript" src="https://www.azadvertizer.net/azure-mg-sub-governance-reporting/hover.js"></script>
    <script src="https://use.fontawesome.com/0c0b5cbde8.js"></script>
</head>
<body style="display: flex; height: 100%; flex-direction: column">
    <div class="tree">
        <div class="hierachyTree">
            <ul>
                <li>
                    <a style="Background-Color:#DDDDDA" href="#"><b>Tenant</b></a>
                    <ul>
"@    
$script:markdown += @"
::: mermaid`r`n
 graph TD;`r`n
"@
#hierachyTree
mgHierachyFunc -mgChild $managementGroupRootId

$html += @"
                    </ul>
                </li>
            </ul>
        </div>
    </div>
    <div class="hierachyTables">
"@  
#hierachyDetails/Tables
mgHierachyTextFunc -mgChild $managementGroupRootId -mgChildOf "tenant"

$html += @"
    </div>

    <div class="footer">
        Also check <a class="foot" href="https://www.azadvertizer.net" target="_blank"><b>AzAdvertizer</b></a> to keep up with the pace on Azure Governance capabilities <b>|</b> <a class="foot" href="https://www.linkedin.com/in/julianhayward" target="_blank"><i class="fa fa-linkedin-square fa-sm" aria-hidden="true"></i></a>
    </div>

    <script>
        var coll = document.getElementsByClassName("collapsible");
        var i;
        for (i = 0; i < coll.length; i++) {
        coll[i].addEventListener("click", function() {
            this.classList.toggle("active");
            var content = this.nextElementSibling;
            if (content.style.display === "block") {
            content.style.display = "none";
            } else {
            content.style.display = "block";
            }
        });
        }
    </script>
</body>
</html>
"@  

foreach ($mg in $arrayMgs) {
    $stringMgs = $stringMgs + $mg + ","
}
foreach ($sub in $arraySubs) {
    $stringSubs = $stringSubs + $sub + ","
}

$subsstring = $subsstring.TrimEnd(",")
$script:markdown += @"
 classDef mgr fill:#f9f,stroke:#333,stroke-width:4px;
 classDef subs fill:#fee,stroke:#333,stroke-width:4px;
 class $stringMgs mgr;
 class $stringSubs subs;
:::`r`n
"@


$html | Out-File "mg-sub-hierachy_$managementGroupRootId`_$fileTimestamp.html" -Encoding utf8 -Force
$markdown | Out-File "mg-sub-hierachy_$managementGroupRootId`_$fileTimestamp.md" -Encoding utf8 -Force

$subsstring =""
foreach ($sub in $mgSubs) {
    write-output "$sub"
    Write-Output "next"
    $subsstring = $subsstring + $sub + ", "

}

$subsstring = $subsstring.TrimEnd(", ")