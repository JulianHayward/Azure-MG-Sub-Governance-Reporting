<#  
.SYNOPSIS  
    This script creates the following files to help better understand and audit your governance setup
    very detailed csv file
        Management Groups, Subscriptions, Policy, Policy Initiative, RBAC
    detailed html file
        Management Groups, Subscriptions, Policy, Policy Initiative, RBAC
    basic markdown file for use with Azure DevOps Wiki leveraging the Mermaid plugin
        Management Groups, Subscriptions
  
.DESCRIPTION  
    Do you want to have visibility on your Management Group hierarchy, document it in markdown? This script iterates Management Group hierarchy down to Subscription level capturing RBAC Roles, Policies and Policy Initiatives.
 
.PARAMETER managementGroupId
    Define the Management Group Id for which the outputs/files shall be generated
 
.PARAMETER csvDelimiter
    The script outputs a csv file depending on your delimit defaults choose semicolon or comma

.PARAMETER outputPath
    Full- or relative path

.PARAMETER UseAzureRM
    default is Az Module, if you use the paramenter then AzureRM will be used

.EXAMPLE
    PS C:\> .\AzGovViz.ps1 -managementGroupId <your-Management-Group-IdtId>

.EXAMPLE
    Optional parameters:
    PS C:\>.\AzGovViz.ps1 -managementGroupId <your-Management-Group-Id> -csvDelimiter "," -outputPath 123 -UseAzureRM -AzureDevOpsWikiAsCode

.NOTES
    AUTHOR: Julian Hayward - Premier Field Engineer - Azure Infrastucture/Automation/Devops/Governance

    Role assignments to Unknown Object happens when the graph object(User/Group/Service principal) gets deleted from the directory after the Role assignment was created. Since the graph entity is deleted, we cannot figure out the object's displayname or type from graph, due to which we show the objecType as Unknown.
    
    API permissions: If you run the script in Azure Automation or Azure DevOps hosted agent you will need to grant API permissions in Azure Active Directory (get-AzRoleAssignment cmdlet). The Automation Account App registration must be granted with: Azure Active Directory API | Application | Directory | Read.All

.LINK
    https://github.com/JulianHayward/Azure-MG-Sub-Governance-Reporting

#>

[CmdletBinding()]
Param
(
    [Parameter(Mandatory = $True)][string]$ManagementGroupId,
    [string]$CsvDelimiter = ";",
    [string]$OutputPath,
    [switch]$UseAzureRm,
    [switch]$AzureDevOpsWikiAsCode
)

#az/azurerm
if ($UseAzureRM) { 
    $azOrAzureRmModule = 'AzureRm'
}
else{
    $azOrAzureRmModule = 'Az'
}

#check for required cmdlets
#context
$testCommandAzAccounts = "Get-$($azOrAzureRmModule)Context"
if (-not (Get-Command $testCommandAzAccounts -ErrorAction Ignore)) {
    if ($UseAzureRM) { 
        Write-Output "cmdlet $testCommandAzAccounts not available - install ps module $azOrAzureRmModule.Profile"
    }
    else{
        Write-Output "cmdlet $testCommandAzAccounts not available - install ps module $azOrAzureRmModule.Accounts"
    }
	return
}
else{
    Write-Output "passed: $azOrAzureRmModule module supporting cmdlet $testCommandAzAccounts installed"
}
#resources
$testCommandAzResources = "Get-$($azOrAzureRmModule)PolicyDefinition"
if (-not (Get-Command $testCommandAzResources -ErrorAction Ignore)) {
	Write-Output "cmdlet $testCommandAzResources not available - install ps module $azOrAzureRmModule.Resources"
	return
}
else{
    Write-Output "passed: $azOrAzureRmModule module supporting cmdlet $testCommandAzResources installed"
}

#commands
$commandGetPolicyDefinition = "Get-$($azOrAzureRmModule)PolicyDefinition"
$script:command_GetPolicyDefinition = Get-Command $commandGetPolicyDefinition
$commandGetPolicySetDefinition = "Get-$($azOrAzureRmModule)PolicySetDefinition"
$script:command_GetPolicySetDefinition = Get-Command $commandGetPolicySetDefinition
$commandGetPolicyAssignment = "Get-$($azOrAzureRmModule)PolicyAssignment"
$script:command_GetPolicyAssignment = Get-Command $commandGetPolicyAssignment
$commandGetRoleDefinition = "Get-$($azOrAzureRmModule)RoleDefinition"
$script:command_GetRoleDefinition = Get-Command $commandGetRoleDefinition
$commandGetRoleAssignment = "Get-$($azOrAzureRmModule)RoleAssignment"
$script:command_GetRoleAssignment = Get-Command $commandGetRoleAssignment
$commandGetManagementGroup = "Get-$($azOrAzureRmModule)ManagementGroup"
$script:command_GetManagementGroup = Get-Command $commandGetManagementGroup
$commandGetContext = "Get-$($azOrAzureRmModule)Context"
$script:command_GetContext = Get-Command $commandGetContext

#check if connected/login
$checkContext = &$script:command_GetContext
if (-not $checkContext){
    Write-Output "no context found, please login to Azure using connect-$($azOrAzureRmModule)Account at first"
    return
}

#helper file/dir
if (-not [IO.Path]::IsPathRooted($outputPath)){
    $outputPath = Join-Path -Path (Get-Location).Path -ChildPath $outputPath
}
$outputPath = Join-Path -Path $outputPath -ChildPath '.'
$outputPath = [IO.Path]::GetFullPath($outputPath)
if (-not (test-path $outputPath)){
     Write-Output "path $outputPath does not exist -create it!"
     return
}
else{
    Write-Output "output will be created in path $outputPath"
}
$DirectorySeparatorChar = [IO.Path]::DirectorySeparatorChar
$fileTimestamp = (get-date -format "yyyyMMddHHmmss")

if ($AzureDevOpsWikiAsCode) { 
    $fileName = "AzGovViz_$($ManagementGroupId)"
}
else{
    $fileName = "AzGovViz_$($fileTimestamp)_$($ManagementGroupId)"
}

#helper 
$executionDateTimeInternationalReadable = get-date -format "dd-MMM-yyyy HH:mm:ss"
$currentTimeZone = (Get-TimeZone).Id

#MgLevel 
$hierarchyLevel = 0

#region Code
#region table
$table = [System.Data.DataTable]::new("AzGovViz")
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
#endregion table

#region Function
function addRowToTable($hierarchyLevel, $mgName, $mgId, $mgParentId, $mgParentName, $subName, $subId, $Policy, $PolicyType, $PolicyDefinitionIdFull, $PolicyDefinitionIdGuid, $PolicyAssignmentScope, $PolicyAssignmentId, $PolicyVariant, $RoleDefinitionId, $RoleDefinitionName, $RoleAssignmentDisplayname, $RoleAssignmentSignInName, $RoleAssignmentObjectId, $RoleAssignmentObjectType, $RoleAssignmentId, $RoleAssignmentScope, $RoleIsCustom, $RoleAssignableScopes) {
    $row = $table.NewRow()
    $row.Level = $hierarchyLevel
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

#region Function_dataCollection
function dataCollection($mgId, $hierarchyLevel, $mgParentId, $mgParentName) {
    Write-Output "...................."
    $hierarchyLevel++
    $getMg = &$script:command_GetManagementGroup -groupname $mgId -Expand -Recurse
    if (!$getMg){
        write-output "fail - check the provided ManagementGroup Id: '$mgI'"
        return
    }
    Write-Output "Processing L$hierarchyLevel MG-Name:'$($getMg.DisplayName)' MG-ID:'$($getMg.Name)'"
    $L0mgmtGroupPolicyAssignments = &$script:command_GetPolicyAssignment -Scope "/providers/Microsoft.Management/managementGroups/$($getMg.Name)"
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
                        $L0mgmtGroupPolicyDef = &$script:command_GetPolicyDefinition -custom -ManagementGroupName $getMg.Name | Where-Object { $_.policydefinitionid -eq $L0mgmtGroupPolicyAssignment.properties.policydefinitionid }
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
                        $L0mgmtGroupPolicyDef = &$script:command_GetPolicyDefinition | Where-Object { $_.policydefinitionid -eq $L0mgmtGroupPolicyAssignment.properties.policydefinitionid }
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
                addRowToTable -hierarchyLevel $hierarchyLevel -mgName $getMg.DisplayName -mgId $getMg.Name -mgParentId $mgParentId -mgParentName $mgParentName -Policy $Policy -PolicyType $PolicyType -PolicyDefinitionIdFull $PolicyDefinitionIdFull -PolicyDefinitionIdGuid $PolicyDefinitionIdGuid -PolicyAssignmentScope $PolicyAssignmentScope -PolicyAssignmentId $PolicyAssignmentId -PolicyVariant $PolicyVariant -RoleDefinitionId $RoleDefinitionId -RoleDefinitionName $RoleDefinitionName -RoleAssignmentDisplayname $RoleAssignmentDisplayname -RoleAssignmentSignInName $RoleAssignmentSignInName -RoleAssignmentObjectId $RoleAssignmentObjectId -RoleAssignmentObjectType $RoleAssignmentObjectType -RoleAssignmentScope $RoleAssignmentScope -RoleIsCustom $RoleIsCustom -RoleAssignableScopes $RoleAssignableScopes
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
                        #write-output "existing ht policySet entry"
                    }
                    else{
                        #write-output "not existing ht policySet entry"
                        $L0mgmtGroupPolicySetDef = &$script:command_GetPolicySetDefinition -custom -ManagementGroupName $getMg.Name | Where-Object { $_.policysetdefinitionid -eq $L0mgmtGroupPolicyAssignment.properties.policydefinitionid }
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
                        #write-output "existing ht policySet entry"
                    }
                    else{
                        #write-output "not existing ht policySet entry"
                        $L0mgmtGroupPolicySetDef = &$script:command_GetPolicySetDefinition | Where-Object { $_.policysetdefinitionid -eq $L0mgmtGroupPolicyAssignment.properties.policydefinitionid }
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
                addRowToTable -hierarchyLevel $hierarchyLevel -mgName $getMg.DisplayName -mgId $getMg.Name -mgParentId $mgParentId -mgParentName $mgParentName -Policy $Policy -PolicyType $PolicyType -PolicyDefinitionIdFull $PolicyDefinitionIdFull -PolicyDefinitionIdGuid $PolicyDefinitionIdGuid -PolicyAssignmentScope $PolicyAssignmentScope -PolicyAssignmentId $PolicyAssignmentId -PolicyVariant $PolicyVariant -RoleDefinitionId $RoleDefinitionId -RoleDefinitionName $RoleDefinitionName -RoleAssignmentDisplayname $RoleAssignmentDisplayname -RoleAssignmentSignInName $RoleAssignmentSignInName -RoleAssignmentObjectId $RoleAssignmentObjectId -RoleAssignmentObjectType $RoleAssignmentObjectType -RoleAssignmentScope $RoleAssignmentScope -RoleIsCustom $RoleIsCustom -RoleAssignableScopes $RoleAssignableScopes
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
    $L0mgmtGroupRoleAssignments = &$script:command_GetRoleAssignment -scope "/providers/Microsoft.Management/managementGroups/$($getMg.Name)" -verbose
    Write-Output "MG Role Assignments: $($L0mgmtGroupRoleAssignments.count)"
    foreach ($L0mgmtGroupRoleAssignment in $L0mgmtGroupRoleAssignments) {
        #$htRoles
        $roleId = $L0mgmtGroupRoleAssignment.RoleDefinitionId
        if ($htRoles[$L0mgmtGroupRoleAssignment.RoleDefinitionId]){
            #write-output "existing role ht entry"
        }
        else{
            #write-output "not existing role ht entry"
            $L0mgmtGroupRoleDefinition = &$script:command_GetRoleDefinition -Id $L0mgmtGroupRoleAssignment.RoleDefinitionId -Scope $L0mgmtGroupRoleAssignment.Scope -verbose
            if (-not $L0mgmtGroupRoleDefinition){
                $L0mgmtGroupRoleAssignment
                Write-Output "$($L0mgmtGroupRoleAssignment.RoleDefinitionId) not exists"
                $L0mgmtGroupRoleDefinitionId = $L0mgmtGroupRoleAssignment.RoleDefinitionId
                $L0mgmtGroupRoleDefinitionType = "N/A"
                $L0mgmtGroupRoleDefinitionAssignableScopes = "N/A"
            }
            else{
                $L0mgmtGroupRoleDefinitionId = $L0mgmtGroupRoleDefinition.Id
                $L0mgmtGroupRoleDefinitionType = $L0mgmtGroupRoleDefinition.IsCustom
                $L0mgmtGroupRoleDefinitionAssignableScopes = $L0mgmtGroupRoleDefinition.AssignableScopes

            }
            $htRoles.$($roleId) = @{}
            $htRoles.$($roleId).Id = $L0mgmtGroupRoleDefinitionId
            $htRoles.$($roleId).IsCustom = $L0mgmtGroupRoleDefinitionType
            $htRoles.$($roleId).assignableScopes = $L0mgmtGroupRoleDefinitionAssignableScopes
        }  
        $RoleDefinitionId = $L0mgmtGroupRoleAssignment.RoleDefinitionId 
        if (($L0mgmtGroupRoleAssignment.RoleDefinitionName).length -eq 0) {
            $RoleDefinitionName = "This roleDefinition was likely deleted although a roleAssignment existed" 
        }
        else{
            $RoleDefinitionName = $L0mgmtGroupRoleAssignment.RoleDefinitionName
        }
        if (($L0mgmtGroupRoleAssignment.DisplayName).length -eq 0) {
            $RoleAssignmentDisplayname = "N/A" 
        }
        else{
            $RoleAssignmentDisplayname = $L0mgmtGroupRoleAssignment.DisplayName
        }                
        if (($L0mgmtGroupRoleAssignment.SignInName).length -eq 0) {
            $RoleAssignmentSignInName = "N/A" 
        }
        else{
            $RoleAssignmentSignInName = $L0mgmtGroupRoleAssignment.SignInName
        }
        $RoleAssignmentObjectId = $L0mgmtGroupRoleAssignment.ObjectId
        $RoleAssignmentObjectType = $L0mgmtGroupRoleAssignment.ObjectType
        $RoleAssignmentId = $L0mgmtGroupRoleAssignment.RoleAssignmentId
        $RoleAssignmentScope = $L0mgmtGroupRoleAssignment.Scope
        $RoleIsCustom = $htRoles.$($roleId).IsCustom
        $RoleAssignableScopes = [string]$htRoles.$($roleId).assignableScopes
        addRowToTable -hierarchyLevel $hierarchyLevel -mgName $getMg.DisplayName -mgId $getMg.Name -mgParentId $mgParentId -mgParentName $mgParentName -Policy $Policy -PolicyType $PolicyType -PolicyDefinitionIdFull $PolicyDefinitionIdFull -PolicyDefinitionIdGuid $PolicyDefinitionIdGuid -PolicyAssignmentScope $PolicyAssignmentScope -PolicyAssignmentId $PolicyAssignmentId -PolicyVariant $PolicyVariant -RoleDefinitionId $RoleDefinitionId -RoleDefinitionName $RoleDefinitionName -RoleAssignmentDisplayname $RoleAssignmentDisplayname -RoleAssignmentSignInName $RoleAssignmentSignInName -RoleAssignmentObjectId $RoleAssignmentObjectId -RoleAssignmentObjectType $RoleAssignmentObjectType -RoleAssignmentId $RoleAssignmentId -RoleAssignmentScope $RoleAssignmentScope -RoleIsCustom $RoleIsCustom -RoleAssignableScopes $RoleAssignableScopes
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

    Write-Output "L$hierarchyLevel MG Name:'$($getMg.DisplayName)' ID:'$($getMg.Name)' child items: $($getMg.children.count) (MG or Sub)"

    if ($getMg.children.count -gt 0) {
        foreach ($childMg in $getMg.Children | Where-Object { $_.Type -eq "/subscriptions" }) {
            Write-Output "Processing SUB Name:'$($childMg.DisplayName) ID:'$($childMg.Id)''"
            $L1mgmtGroupSubPolicyAssignments = &$script:command_GetPolicyAssignment -Scope "$($childMg.Id)"
            Write-Output "SUB Policy Assignments: $($L1mgmtGroupSubPolicyAssignments.count)"
            foreach ($L1mgmtGroupSubPolicyAssignment in $L1mgmtGroupSubPolicyAssignments) {
                #$htpolicies
                #$htpolicySets
                if ($L1mgmtGroupSubPolicyAssignment.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/" -OR $L1mgmtGroupSubPolicyAssignment.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policySetDefinitions/") {
                    $policyId = ($L1mgmtGroupSubPolicyAssignment.properties.policydefinitionid -replace '.*/')
                    if ($L1mgmtGroupSubPolicyAssignment.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/") {
                        $PolicyVariant = "Policy"
                        if ($htPolicies[$policyId]){
                            #write-output "existing ht policy entry"
                        }
                        else{
                            #write-output "not existing ht policy entry"
                            $L1mgmtGroupSubPolicyDef = &$script:command_GetPolicyDefinition -Id $L1mgmtGroupSubPolicyAssignment.properties.policydefinitionid
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
                        addRowToTable -hierarchyLevel $hierarchyLevel -mgName $getMg.DisplayName -mgId $getMg.Name -mgParentId $mgParentId -mgParentName $mgParentName -subName $childMg.DisplayName -subId $childMg.Id -Policy $Policy -PolicyType $PolicyType -PolicyDefinitionIdFull $PolicyDefinitionIdFull -PolicyDefinitionIdGuid $PolicyDefinitionIdGuid -PolicyAssignmentScope $PolicyAssignmentScope -PolicyAssignmentId $PolicyAssignmentId -PolicyVariant $PolicyVariant -RoleDefinitionId $RoleDefinitionId -RoleDefinitionName $RoleDefinitionName -RoleAssignmentDisplayname $RoleAssignmentDisplayname -RoleAssignmentSignInName $RoleAssignmentSignInName -RoleAssignmentObjectId $RoleAssignmentObjectId -RoleAssignmentObjectType $RoleAssignmentObjectType -RoleAssignmentScope $RoleAssignmentScope -RoleIsCustom $RoleIsCustom -RoleAssignableScopes $RoleAssignableScopes
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
                            #write-output "existing ht policySet entry"
                        }
                        else{
                            #write-output "not existing ht policySet entry"
                            $L1mgmtGroupSubPolicySetDef = &$script:command_GetPolicySetDefinition -Id $L1mgmtGroupSubPolicyAssignment.properties.policydefinitionid
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
                        addRowToTable -hierarchyLevel $hierarchyLevel -mgName $getMg.DisplayName -mgId $getMg.Name -mgParentId $mgParentId -mgParentName $mgParentName -subName $childMg.DisplayName -subId $childMg.Id -Policy $Policy -PolicyType $PolicyType -PolicyDefinitionIdFull $PolicyDefinitionIdFull -PolicyDefinitionIdGuid $PolicyDefinitionIdGuid -PolicyAssignmentScope $PolicyAssignmentScope -PolicyAssignmentId $PolicyAssignmentId -PolicyVariant $PolicyVariant -RoleDefinitionId $RoleDefinitionId -RoleDefinitionName $RoleDefinitionName -RoleAssignmentDisplayname $RoleAssignmentDisplayname -RoleAssignmentSignInName $RoleAssignmentSignInName -RoleAssignmentObjectId $RoleAssignmentObjectId -RoleAssignmentObjectType $RoleAssignmentObjectType -RoleAssignmentScope $RoleAssignmentScope -RoleIsCustom $RoleIsCustom -RoleAssignableScopes $RoleAssignableScopes
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
            $L1mgmtGroupSubRoleAssignments = &$script:command_GetRoleAssignment -Scope "$($childMg.Id)" | where-object { $_.RoleAssignmentId -notmatch "$($childMg.Id)/resourcegroups/" } #exclude rg roleassignments
            Write-Output "SUB Role Assignments: $($L1mgmtGroupSubRoleAssignments.count)"
            foreach ($L1mgmtGroupSubRoleAssignment in $L1mgmtGroupSubRoleAssignments) {
                $roleId = $L1mgmtGroupSubRoleAssignment.RoleDefinitionId
                if ($htRoles[$L1mgmtGroupSubRoleAssignment.RoleDefinitionId]){
                    #write-output "existing role ht entry"
                }
                else{
                    #write-output "not existing role ht entry"
                    $L1mgmtGroupSubRoleDefinition = &$script:command_GetRoleDefinition -Id $L1mgmtGroupSubRoleAssignment.RoleDefinitionId -Scope $L1mgmtGroupSubRoleAssignment.Scope
                    if (-not $L1mgmtGroupSubRoleDefinition){
                        $L1mgmtGroupSubRoleAssignment
                        Write-Output "$($L1mgmtGroupSubRoleAssignment.RoleDefinitionId) not exists"
                        $L1mgmtGroupSubRoleDefinitionId = $L1mgmtGroupSubRoleAssignment.RoleDefinitionId
                        $L1mgmtGroupSubRoleDefinitionType = "N/A"
                        $L1mgmtGroupSubRoleDefinitionAssignableScopes = "N/A"
                    }
                    else{
                        $L1mgmtGroupSubRoleDefinitionId = $L1mgmtGroupSubRoleDefinition.Id
                        $L1mgmtGroupSubRoleDefinitionType = $L1mgmtGroupSubRoleDefinition.IsCustom
                        $L1mgmtGroupSubRoleDefinitionAssignableScopes = $L1mgmtGroupSubRoleDefinition.AssignableScopes

                    }
                    $htRoles.$($roleId) = @{}
                    $htRoles.$($roleId).Id = $L1mgmtGroupSubRoleDefinitionId
                    $htRoles.$($roleId).IsCustom = $L1mgmtGroupSubRoleDefinitionType
                    $htRoles.$($roleId).assignableScopes = $L1mgmtGroupSubRoleDefinitionAssignableScopes
                }  
                $RoleDefinitionId = $L1mgmtGroupSubRoleAssignment.RoleDefinitionId 
                if (($L1mgmtGroupSubRoleAssignment.RoleDefinitionName).length -eq 0) {
                    $RoleDefinitionName = "This roleDefinition was likely deleted although a roleAssignment existed" 
                }
                else{
                    $RoleDefinitionName = $L1mgmtGroupSubRoleAssignment.RoleDefinitionName
                }
                if (($L1mgmtGroupSubRoleAssignment.DisplayName).length -eq 0) {
                    $RoleAssignmentDisplayname = "N/A" 
                }
                else{
                    $RoleAssignmentDisplayname = $L1mgmtGroupSubRoleAssignment.DisplayName
                }                
                if (($L1mgmtGroupSubRoleAssignment.SignInName).length -eq 0) {
                    $RoleAssignmentSignInName = "N/A" 
                }
                else{
                    $RoleAssignmentSignInName = $L1mgmtGroupSubRoleAssignment.SignInName
                }                     
                $RoleAssignmentObjectId = $L1mgmtGroupSubRoleAssignment.ObjectId
                $RoleAssignmentObjectType = $L1mgmtGroupSubRoleAssignment.ObjectType
                $RoleAssignmentId = $L1mgmtGroupSubRoleAssignment.RoleAssignmentId
                $RoleAssignmentScope = $L1mgmtGroupSubRoleAssignment.Scope
                $RoleIsCustom = $htRoles.$($roleId).IsCustom
                $RoleAssignableScopes = [string]$htRoles.$($roleId).assignableScopes
                addRowToTable -hierarchyLevel $hierarchyLevel -mgName $getMg.DisplayName -mgId $getMg.Name -mgParentId $mgParentId -mgParentName $mgParentName -subName $childMg.DisplayName -subId $childMg.Id -Policy $Policy -PolicyType $PolicyType -PolicyDefinitionIdFull $PolicyDefinitionIdFull -PolicyDefinitionIdGuid $PolicyDefinitionIdGuid -PolicyAssignmentScope $PolicyAssignmentScope -PolicyAssignmentId $PolicyAssignmentId -RoleDefinitionId $RoleDefinitionId -RoleDefinitionName $RoleDefinitionName -RoleAssignmentDisplayname $RoleAssignmentDisplayname -RoleAssignmentSignInName $RoleAssignmentSignInName -RoleAssignmentObjectId $RoleAssignmentObjectId -RoleAssignmentObjectType $RoleAssignmentObjectType -RoleAssignmentId $RoleAssignmentId -RoleAssignmentScope $RoleAssignmentScope -RoleIsCustom $RoleIsCustom -RoleAssignableScopes $RoleAssignableScopes
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
            Write-Output "Trigger: MG-Name:'$($childMg.DisplayName)' MG-ID:'$($childMg.Name)'"
            dataCollection -mgId $childMg.Name -hierarchyLevel $hierarchyLevel -mgParentId $getMg.Name -mgParentName $getMg.DisplayName
        }
    }
}
#endregion Function_dataCollection

#HTML
function hierarchyMgHTML($mgChild) {
    write-output "processingInFunction: $mgChild"
    #$subscriptions = ($table | Where-Object { "" -ne $_.Subscription -and $_.MgId -eq $mgChild }).Subscription | Get-Unique
    $mgName = ($table | Where-Object { $_.MgId -eq $mgChild }).mgName | Get-Unique
    if ($mgChild -eq (&$script:command_GetContext).Tenant.Id){
        $class= "tenantRootGroup"
    }
    else{
        $class= "aMg"       
    }
$script:html += @"
                    <li><a class="$class" href="#$mgChild"><p id="hierarchy_$mgChild"><img src="https://www.azadvertizer.net/azure-mg-sub-governance-reporting/Icon-general-11-Management-Groups.svg"><br>$mgName<br><i>$mgChild</i></p></a>
"@
    write-output "checking for childMgs for $mgChild"
    $childMgs = ($table | Where-Object { $_.mgParentId -eq "$mgChild" }).MgId | Get-Unique
    if ($childMgs.count -gt 0){
$script:html += @"
                <ul>
"@
        foreach ($childMg in $childMgs){
            write-output "processingFMg: $childMg"
            #$childMgName = ($table | Where-Object {$_.MgId -eq $childMg }).MgName | Get-Unique
            hierarchyMgHTML -mgChild $childMg
        }
        hierarchySubForMgHTML -mgChild $mgChild
$script:html += @"
                </ul>
            </li>    
"@
    }
    else{
        write-output "processingF: no childMgs for $mgChild"
        hierarchySubForMgUlHTML -mgChild $mgChild

$script:html += @"
            </li>
"@
    }
}

function hierarchySubForMgHTML($mgChild) {
#sub
    write-output "checking for Subs for $mgChild"
    $subscriptions = ($table | Where-Object { "" -ne $_.Subscription -and $_.MgId -eq $mgChild }).SubscriptionId | Get-Unique
    if ($subscriptions.Count -gt 0){
        foreach ($subscriptionId in $subscriptions){
            $subscription = ($table | Where-Object { "$subscriptionId" -eq $_.SubscriptionId -and $_.MgId -eq $mgChild }).Subscription | Get-Unique
            write-output "subscription: $subscription"
        }
$script:html += @"
                    <li><a class="aSub" href="#$mgChild"><p id="hierarchySub_$mgChild"><img src="https://www.azadvertizer.net/azure-mg-sub-governance-reporting/Icon-general-2-Subscriptions.svg"><br>$($subscriptions.Count)x<br>Subscription</p></a></li>
"@
    }
}

function hierarchySubForMgUlHTML($mgChild) {
    write-output "checking for Subs for $mgChild"
    $subscriptions = ($table | Where-Object { "" -ne $_.Subscription -and $_.MgId -eq $mgChild }).SubscriptionId | Get-Unique
    if ($subscriptions.Count -gt 0){
$script:html += @"
                <ul>
"@
        foreach ($subscriptionId in $subscriptions){
            $subscription = ($table | Where-Object { "$subscriptionId" -eq $_.SubscriptionId -and $_.MgId -eq $mgChild }).Subscription | Get-Unique
            write-output "subscription: $subscription"
$script:html += @"
        
"@
        }
$script:html += @"
                    <li><a class="aSub" href="#$mgChild"><p id="hierarchySub_$mgChild"><img src="https://www.azadvertizer.net/azure-mg-sub-governance-reporting/Icon-general-2-Subscriptions.svg"><br>$($subscriptions.Count)x<br>Subscription</p></a></li></ul>
"@
    }
}

function tableMgHTML($mgChild, $mgChildOf) {
    write-output "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    write-output "processingInFunction: $mgChild"
    $mgName = ($table | Where-Object {$_.MgId -eq "$mgChild"}).mgName | Get-Unique
    $mgChildOfName = ($table | Where-Object {$_.MgId -eq "$mgChildOf"}).mgName | Get-Unique
    #POLICY
    $policyReleatedQuery = $table | Where-Object { $_.MgId -eq $mgChild -and "" -ne $_.Policy -and "" -eq $_.Subscription }
    $policiesCount = ($policyReleatedQuery | where-object { $_.PolicyVariant -eq "Policy" }).count
    $policiesCountBuiltin = ($policyReleatedQuery | where-object { $_.PolicyVariant -eq "Policy" -and $_.PolicyType -eq "BuiltIn" }).count
    $policiesCountCustom = ($policyReleatedQuery | where-object { $_.PolicyVariant -eq "Policy" -and $_.PolicyType -eq "Custom" }).count
    $policiesAssigned = $policyReleatedQuery | where-object { $_.PolicyVariant -eq "Policy" } | Sort-Object -Property Policy, PolicyType
    $policySetsCount = ($policyReleatedQuery | where-object { $_.PolicyVariant -eq "PolicySet" }).count
    $policySetsCountBuiltin = ($policyReleatedQuery | where-object { $_.PolicyVariant -eq "PolicySet" -and $_.PolicyType -eq "BuiltIn" }).count
    $policySetsCountCustom = ($policyReleatedQuery | where-object { $_.PolicyVariant -eq "PolicySet" -and $_.PolicyType -eq "Custom" }).count
    $policySetsAssigned = $policyReleatedQuery | where-object { $_.PolicyVariant -eq "PolicySet" } | Sort-Object -Property Policy, PolicyType
    $policiesInherited = ($policyReleatedQuery | where-object { $_.PolicyVariant -eq "Policy" -and $_.PolicyAssignmentId -notmatch "/providers/Microsoft.Management/managementGroups/$mgChild/" }).count
    $policySetsInherited = ($policyReleatedQuery | where-object { $_.PolicyVariant -eq "PolicySet" -and $_.PolicyAssignmentId -notmatch "/providers/Microsoft.Management/managementGroups/$mgChild/" }).count
    $scopePolicies = (($policyReleatedQuery| Where-Object { $_.PolicyVariant -eq "Policy" -and $_.PolicyDefinitionIdFull -match "/providers/Microsoft.Management/managementGroups/$mgChild/" }))
    $scopePoliciesCount = (($policyReleatedQuery| Where-Object { $_.PolicyVariant -eq "Policy" -and $_.PolicyDefinitionIdFull -match "/providers/Microsoft.Management/managementGroups/$mgChild/" }).PolicyDefinitionIdFull | sort-object -Unique ).count
    $scopePolicySets = (($policyReleatedQuery| Where-Object { $_.PolicyVariant -eq "PolicySet" -and $_.PolicyDefinitionIdFull -match "/providers/Microsoft.Management/managementGroups/$mgChild/" }))
    $scopePolicySetsCount = (($policyReleatedQuery| Where-Object { $_.PolicyVariant -eq "PolicySet" -and $_.PolicyDefinitionIdFull -match "/providers/Microsoft.Management/managementGroups/$mgChild/" }).PolicyDefinitionIdFull | sort-object -Unique ).count
    #RBAC
    $rbacReleatedQuery = $table | Where-Object { $_.MgId -eq $mgChild -and "" -eq $_.Subscription -and "" -ne $_.RoleDefinitionName }
    $rolesAssigned = $rbacReleatedQuery
    $rolesAssignedCount = $rbacReleatedQuery.count
    $rolesAssignedCountUser = ($rbacReleatedQuery | Where-Object { $_.RoleAssignmentObjectType -eq "User" }).count
    $rolesAssignedCountGroup = ($rbacReleatedQuery | Where-Object { $_.RoleAssignmentObjectType -eq "Group" }).count
    $rolesAssignedCountServicePrincipal = ($rbacReleatedQuery | Where-Object { $_.RoleAssignmentObjectType -eq "ServicePrincipal" }).count
    $rolesAssignedCountUnknown = ($rbacReleatedQuery | Where-Object { $_.RoleAssignmentObjectType -eq "Unknown" }).count
    $rolesAssignedInherited = ($rbacReleatedQuery | Where-Object { $_.RoleAssignmentId -notmatch "/providers/Microsoft.Management/managementGroups/$mgChild/" }).count
$script:html += @"
    <br>
    <table>
        <tr id="$mgChild">
            <th class="mg">
                <img class="imgTable" src="https://www.azadvertizer.net/azure-mg-sub-governance-reporting/Icon-general-11-Management-Groups.svg"> <span><b>$mgName</b> (Id: $mgChild)</span>
            </th>
        </tr>
        <tr>
            <td>
                <p><a href="#hierarchy_$mgChild"><i class="fa fa-eye" aria-hidden="true"></i> <i>Highlight MG in hierarchy</i></a></p>
            </td>
        </tr>
        <tr>
            <td>
                <p>Child of '$mgChildOfName' (Id: $mgChildOf)</p>
            </td>
        </tr>
        <tr>
            <td>
"@
    write-output "creating mgDetailsTable content"    
    tableMgSubDetailsHTML -mgOrSub "mg" -policiesCount $policiesCount -policiesAssigned  $policiesAssigned -policiesCountBuiltin $policiesCountBuiltin -policiesCountCustom $policiesCountCustom -policySetsCount $policySetsCount -policySetsAssigned $policySetsAssigned -policySetsCountBuiltin $policySetsCountBuiltin -policySetsCountCustom $policySetsCountCustom -policiesInherited $policiesInherited -policySetsInherited $policySetsInherited -scopePolicies $scopePolicies -scopePoliciesCount $scopePoliciesCount -scopePolicySets $scopePolicySets -scopePolicySetsCount $scopePolicySetsCount -rolesAssigned $rolesAssigned -rolesAssignedCount $rolesAssignedCount -rolesAssignedInherited $rolesAssignedInherited -rolesAssignedCountUser $rolesAssignedCountUser -rolesAssignedCountGroup $rolesAssignedCountGroup -rolesAssignedCountServicePrincipal $rolesAssignedCountServicePrincipal -rolesAssignedCountUnknown $rolesAssignedCountUnknown
    write-output "checking for subs for $mgChild"
    tableSubForMgHTML -mgChild $mgChild
    $childMgs = ($table | Where-Object {$_.mgParentId -eq "$mgChild"}).MgId | sort-object -Unique
    if ($childMgs.count -gt 0){
        foreach ($childMg in $childMgs){
            write-output "checking for childmgs for $mgChild"
            tableMgHTML -mgChild $childMg -mgChildOf $mgChild
        }
    }
    else{
        write-output "no childMgs for $mgChild"
    }
}

function tableSubForMgHTML($mgChild) {
    write-output "checking for Subs for $mgChild"
    $subscriptions = ($table | Where-Object { "" -ne $_.Subscription -and $_.MgId -eq $mgChild }).SubscriptionId | Get-Unique
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
            $subscription = ($table | Where-Object { "$subscriptionId" -eq $_.SubscriptionId -and $_.MgId -eq $mgChild }).Subscription | Get-Unique
            write-output "subscriptionId: $subscriptionId"
            #POLICY
            $policyReleatedQuery = $table | Where-Object { $_.SubscriptionId -eq "$subscriptionId" -and "" -ne $_.Policy }
            $policiesCount = ($policyReleatedQuery | where-object { $_.PolicyVariant -eq "Policy" }).count
            $policiesCountBuiltin = ($policyReleatedQuery | where-object { $_.PolicyVariant -eq "Policy" -and $_.PolicyType -eq "BuiltIn" }).count
            $policiesCountCustom = ($policyReleatedQuery | where-object { $_.PolicyVariant -eq "Policy" -and $_.PolicyType -eq "Custom" }).count
            $policiesAssigned = $policyReleatedQuery | where-object { $_.PolicyVariant -eq "Policy" } | Sort-Object -Property Policy, PolicyType
            $policiesInherited = ($policyReleatedQuery | where-object { $_.PolicyVariant -eq "Policy" -and $_.PolicyAssignmentId -notmatch "$subscriptionId/" }).count

            $policySetsCount = ($policyReleatedQuery | where-object { $_.PolicyVariant -eq "PolicySet" }).count
            $policySetsCountBuiltin = ($policyReleatedQuery | where-object { $_.PolicyVariant -eq "PolicySet" -and $_.PolicyType -eq "BuiltIn" }).count
            $policySetsCountCustom = ($policyReleatedQuery | where-object { $_.PolicyVariant -eq "PolicySet" -and $_.PolicyType -eq "Custom" }).count
            $policySetsAssigned = $policyReleatedQuery | where-object { $_.PolicyVariant -eq "PolicySet" } | Sort-Object -Property Policy, PolicyType
            $policySetsInherited = ($policyReleatedQuery | where-object {$_.PolicyVariant -eq "PolicySet" -and $_.PolicyAssignmentId -notmatch "$subscriptionId/" }).count

            $scopePolicies = (($policyReleatedQuery| Where-Object { $_.PolicyVariant -eq "Policy" -and $_.PolicyDefinitionIdFull -match "$subscriptionId/" }))
            $scopePoliciesCount = (($policyReleatedQuery| Where-Object { $_.PolicyVariant -eq "Policy" -and $_.PolicyDefinitionIdFull -match "$subscriptionId/" }).PolicyDefinitionIdFull | sort-object -Unique ).count
            $scopePolicySets = (($policyReleatedQuery| Where-Object { $_.PolicyVariant -eq "PolicySet" -and $_.PolicyDefinitionIdFull -match "$subscriptionId/" }))
            $scopePolicySetsCount = (($policyReleatedQuery| Where-Object { $_.PolicyVariant -eq "PolicySet" -and $_.PolicyDefinitionIdFull -match "$subscriptionId/" }).PolicyDefinitionIdFull | sort-object -Unique ).count
            #RBAC
            $rbacReleatedQuery = $table | Where-Object { $_.SubscriptionId -eq "$subscriptionId" -and "" -ne $_.RoleDefinitionName }
            $rolesAssigned = $rbacReleatedQuery
            $rolesAssignedCount = $rbacReleatedQuery.count
            $rolesAssignedCountUser = ($rbacReleatedQuery | Where-Object { $_.RoleAssignmentObjectType -eq "User" }).count
            $rolesAssignedCountGroup = ($rbacReleatedQuery | Where-Object { $_.RoleAssignmentObjectType -eq "Group" }).count
            $rolesAssignedCountServicePrincipal = ($rbacReleatedQuery | Where-Object { $_.RoleAssignmentObjectType -eq "ServicePrincipal" }).count
            $rolesAssignedCountUnknown = ($rbacReleatedQuery | Where-Object { $_.RoleAssignmentObjectType -eq "Unknown" }).count
            $rolesAssignedInherited = ($rbacReleatedQuery | Where-Object { $_.RoleAssignmentId -notmatch "$subscriptionId/" }).count
$script:html += @"
    <tr>
        <th>
            <img class="imgTable" src="https://www.azadvertizer.net/azure-mg-sub-governance-reporting/Icon-general-2-Subscriptions.svg"> <span id="$subscriptionId"><b>$subscription</b> (Id: $($subscriptionId -replace '.*/'))</span>
        </th>
    </tr>
    <tr>
        <td>
            <p><a href="#hierarchySub_$mgChild"><i class="fa fa-eye" aria-hidden="true"></i> <i>Highlight Sub in hierarchy</i></a></p>
        </td>
    </tr>
    <tr>
        <td>
"@

tableMgSubDetailsHTML -mgOrSub "sub" -policiesCount $policiesCount -policiesAssigned $policiesAssigned -policiesCountBuiltin $policiesCountBuiltin -policiesCountCustom $policiesCountCustom -policySetsCount $policySetsCount -policySetsAssigned $policySetsAssigned -policySetsCountBuiltin $policySetsCountBuiltin -policySetsCountCustom $policySetsCountCustom -policiesInherited $policiesInherited -policySetsInherited $policySetsInherited -scopePolicies $scopePolicies -scopePoliciesCount $scopePoliciesCount -scopePolicySets $scopePolicySets -scopePolicySetsCount $scopePolicySetsCount -rolesAssigned $rolesAssigned -rolesAssignedCount $rolesAssignedCount -rolesAssignedInherited $rolesAssignedInherited -rolesAssignedCountUser $rolesAssignedCountUser -rolesAssignedCountGroup $rolesAssignedCountGroup -rolesAssignedCountServicePrincipal $rolesAssignedCountServicePrincipal -rolesAssignedCountUnknown $rolesAssignedCountUnknown

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

function tableMgSubDetailsHTML($mgOrSub, $policiesCount, $policiesAssigned, $policySetsCount, $policySetsAssigned, $policiesInherited, $policySetsInherited, $scopePolicies, $scopePoliciesCount, $scopePolicySets, $scopePolicySetsCount, $rolesAssigned, $rolesAssignedCount, $rolesAssignedInherited){

if ($mgOrSub -eq "mg"){
    $cssClass = "mgDetailsTable"
}
if ($mgOrSub -eq "sub"){
    $cssClass = "subDetailsTable"
}

if ($policiesCount -gt 0){

$script:html += @"
    <button type="button" class="collapsible"><p><i class="fa fa-plus" aria-hidden="true"></i> $policiesCount Policy Assignment(s) (Builtin: $policiesCountBuiltin | Custom: $policiesCountCustom) ($policiesInherited inherited)</p></button>
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
            <p><i class="fa fa-minus" aria-hidden="true"></i> $policiesCount Policy Assignment(s) (Builtin: $policiesCountBuiltin | Custom: $policiesCountCustom) ($policiesInherited inherited)</p>
"@
        }
$script:html += @"
        </td></tr>
        <tr><td>
"@
        if ($policySetsCount -gt 0){
    
$script:html += @"
    <button type="button" class="collapsible"><p><i class="fa fa-plus" aria-hidden="true"></i> $policySetsCount PolicySet Assignment(s) (Builtin: $policySetsCountBuiltin | Custom: $policySetsCountCustom) ($policySetsInherited inherited)</p></button>
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
            <p><i class="fa fa-minus" aria-hidden="true"></i> $policySetsCount PolicySet Assignment(s) (Builtin: $policySetsCountBuiltin | Custom: $policySetsCountCustom) ($policySetsInherited inherited)</p>
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
        <button type="button" class="collapsible"><p><i class="fa fa-plus" aria-hidden="true"></i> $rolesAssignedCount Role Assignment(s) (User: $rolesAssignedCountUser | Group: $rolesAssignedCountGroup | ServicePrincipal: $rolesAssignedCountServicePrincipal | Unknown: $rolesAssignedCountUnknown) ($rolesAssignedInherited inherited)</p></button>
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
                        $roleWithWithoutLinkToAzAdvertizer = "<a href=`"https://www.azadvertizer.net/azrolesadvertizer/$($roleAssigned.RoleDefinitionId).html`" target=`"_blank`"><i class=`"fa fa-link`" aria-hidden=`"true`"></i> $($roleAssigned.RoleDefinitionName)</a>"
                        #$roleWithWithoutLinkToAzAdvertizer = $roleAssigned.RoleDefinitionName
                    }
                    else{
                        $roleType = "Custom"
                        $roleWithWithoutLinkToAzAdvertizer = $roleAssigned.RoleDefinitionName
                    }
                    if (($roleAssigned.RoleAssignmentDisplayname).length -eq 1){
                        $objDisplayName = "N/A"
                    }
                    else{
                        $objDisplayName = $roleAssigned.RoleAssignmentDisplayname
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
                        $objDisplayName
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
                <p><i class="fa fa-minus" aria-hidden="true"></i> $rolesAssignedCount Role Assignment(s) (User: $rolesAssignedCountUser | Group: $rolesAssignedCountGroup | ServicePrincipal: $rolesAssignedCountServicePrincipal | Unknown: $rolesAssignedCountUnknown) ($rolesAssignedInherited inherited)</p>
"@
            }
$script:html += @"
                </td></tr>
                <tr><td>
"@
}

#MD
function diagramMermaid() {
    $mgLevels = ($table | Sort-Object -Property Level -Unique).Level
    foreach ($mgLevel in $mgLevels){
        $mgsInLevel = ($table | Where-Object { $_.Level -eq $mgLevel}).MgId | Get-Unique
        foreach ($mgInLevel in $mgsInLevel){ 
            $mgName = ($table | Where-Object { $_.Level -eq $mgLevel -and $_.MgId -eq $mgInLevel }).MgName | Get-Unique
            $mgParentId = ($table | Where-Object { $_.Level -eq $mgLevel -and $_.MgId -eq $mgInLevel }).mgParentId | Get-Unique
            $mgParentName = ($table | Where-Object { $_.Level -eq $mgLevel -and $_.MgId -eq $mgInLevel }).mgParentName | Get-Unique
            if ($mgInLevel -ne $getMgParentId){
                $script:arrayMgs += $mgInLevel
            }
$script:markdownhierarchyMgs += @"
$mgParentId($mgParentName<br>$mgParentId) --> $mgInLevel($mgName<br>$mgInLevel)`n
"@
            $subsUnderMg = ($table | Where-Object { $_.Level -eq $mgLevel -and "" -ne $_.Subscription -and $_.MgId -eq $mgInLevel }).SubscriptionId | Get-Unique
            if ($subsUnderMg.count -gt 0){
                foreach ($subUnderMg in $subsUnderMg){
                    $script:arraySubs += "SubsOf$mgInLevel"
                    $mgName = ($table | Where-Object { $_.Level -eq $mgLevel -and $_.MgId -eq $mgInLevel }).MgName | Get-Unique
                    $mgParentId = ($table | Where-Object { $_.Level -eq $mgLevel -and $_.MgId -eq $mgInLevel }).MgParentId | Get-Unique
                    $mgParentName = ($table | Where-Object { $_.Level -eq $mgLevel -and $_.MgId -eq $mgInLevel }).MgParentName | Get-Unique
                    $subName = ($table | Where-Object { $_.Level -eq $mgLevel -and $_.MgId -eq $mgInLevel -and $_.SubscriptionId -eq $subUnderMg }).Subscription | Get-Unique
$script:markdownTable += @"
| $mgLevel | $mgName | $mgInLevel | $mgParentName | $mgParentId | $subName | $($subUnderMg -replace '.*/') |`n
"@
                }
                $mgName = ($table | Where-Object { $_.Level -eq $mgLevel -and $_.MgId -eq $mgInLevel }).MgName | Get-Unique
$script:markdownhierarchySubs += @"
$mgInLevel($mgName<br>$mgInLevel) --> SubsOf$mgInLevel(($($subsUnderMg.count)))`n
"@
            }
            else{
                $mgName = ($table | Where-Object { $_.Level -eq $mgLevel -and $_.MgId -eq $mgInLevel }).MgName | Get-Unique
                $mgParentId = ($table | Where-Object { $_.Level -eq $mgLevel -and $_.MgId -eq $mgInLevel }).MgParentId | Get-Unique
                $mgParentName = ($table | Where-Object { $_.Level -eq $mgLevel -and $_.MgId -eq $mgInLevel }).MgParentName | Get-Unique
$script:markdownTable += @"
| $mgLevel | $mgName | $mgInLevel | $mgParentName | $mgParentId | none | none |`n
"@
            }
        }
    }
}
#endregion Function

#region dataCollection
if ((&$script:command_GetContext).Tenant.Id -ne $ManagementGroupId) {
    #managementGroupId is not RootMgId - get the parents..
    $getMgParent = &$script:command_GetManagementGroup -GroupName $ManagementGroupId
    if (!$getMgParent){
        write-output "fail - check the provided ManagementGroup Id: '$ManagementGroupId'"
        return
    }
    $getMgParentId = $getMgParent.ParentName
    $getMgParentName = $getMgParent.ParentDisplayName
    $mermaidprnts = "'$((&$script:command_GetContext).Tenant.Id)',$getMgParentId"
    $l++
    addRowToTable -hierarchyLevel $hierarchyLevel -mgName $getMgParentName -mgId $getMgParentId -mgParentId "'$((&$script:command_GetContext).Tenant.Id)'" -mgParentName "Tenant" -Policy "N/A" -PolicyType "N/A" -PolicyDefinitionIdFull "N/A" -PolicyDefinitionIdGuid "N/A" -PolicyAssignmentScope "N/A" -PolicyAssignmentId "N/A" -PolicyVariant "N/A" -RoleDefinitionId "N/A" -RoleDefinitionName "N/A" -RoleAssignmentDisplayname "N/A" -RoleAssignmentSignInName "N/A" -RoleAssignmentObjectId "N/A" -RoleAssignmentObjectType "N/A" -RoleAssignmentScope "N/A" -RoleIsCustom "N/A" -RoleAssignableScopes "N/A"
}
else{
    $getMgParentId = "'$ManagementGroupId'"
    $getMgParentName = "Tenant"
    $mermaidprnts = "'$getMgParentId',$getMgParentId"
}
dataCollection -mgId $ManagementGroupId -hierarchyLevel $hierarchyLevel -mgParentId $getMgParentId -mgParentName $getMgParentName
#endregion dataCollection

#region createoutputs

#region BuildCSV
$table | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).csv" -Delimiter "$csvDelimiter" -NoTypeInformation
#endregion BuildCSV

#region BuildHTML
$html = $null

$parentMgNamex = ($table | Where-Object { $_.MgParentId -eq $getMgParentId }).mgParentName | Get-Unique
$parentMgIdx = ($table | Where-Object { $_.MgParentId -eq $getMgParentId }).mgParentId | Get-Unique

$html += @"
<!doctype html>
<html lang="en">
<html style="height: 100%">
<head>
    <meta charset="utf-8" />
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate" />
    <meta http-equiv="Pragma" content="no-cache" />
    <meta http-equiv="Expires" content="0" />
    <title>AzGovViz</title>
    <link rel="stylesheet" type="text/css" href="https://www.azadvertizer.net/azure-mg-sub-governance-reporting/hierarchy_202003252354.css">
    <!--<link rel="stylesheet" type="text/css" href="../hierarchy_202003252354.css">-->
    <script src="https://code.jquery.com/jquery-1.7.2.js" integrity="sha256-FxfqH96M63WENBok78hchTCDxmChGFlo+/lFIPcZPeI=" crossorigin="anonymous"></script>
    <script src="https://code.jquery.com/ui/1.8.18/jquery-ui.js" integrity="sha256-lzf/CwLt49jbVoZoFcPZOc0LlMYPFBorVSwMsTs2zsA=" crossorigin="anonymous"></script>
    <script type="text/javascript" src="https://www.azadvertizer.net/azure-mg-sub-governance-reporting/hover.js"></script>
    <script src="https://use.fontawesome.com/0c0b5cbde8.js"></script>
</head>
<body style="display: flex; height: 100%; flex-direction: column">
    <div class="tree">
        <div class="hierarchyTree">
"@

if ($getMgParentName -eq "Tenant"){
$html += @"
            <ul>
                <li>
                    <a class="tenant" style="Background-Color:#DDDDDA" href="#"><b>Tenant</b><br><i>$getMgParentId</i></a>
                    <ul>
"@
}
else{
$html += @"
            <ul>
                <li>
                    <a class="tenant" style="Background-Color:#DDDDDA" href="#"><b>Tenant</b><br><i>$((&$script:command_GetContext).Tenant.Id)</i></a>
                    <ul>
                        <li><a style="Background-Color:#EEEEEE" href="#"><img src="https://www.azadvertizer.net/azure-mg-sub-governance-reporting/Icon-general-11-Management-Groups.svg"><p>$parentMgNamex<br><i>$parentMgIdx</i></p></a>
                            <ul>
"@
}

hierarchyMgHTML -mgChild $ManagementGroupId


if ($getMgParentName -eq "Tenant"){
    $html += @"
                        </ul>
                    </li>
                </ul>
            </div>
        </div>
    <div class="hierarchyTables">
"@
}
else{
$html += @"
                                </ul>
                            </li>
                        </ul>
                    </li>
                </ul>
            </div>
        </div>
    <div class="hierarchyTables">
"@
}

tableMgHTML -mgChild $ManagementGroupId -mgChildOf $getMgParentId

$html += @"
    </div>

    <div class="footer">
    <b>AzGovViz</b> check for latest release on GitHub <a href="https://github.com/JulianHayward/Azure-MG-Sub-Governance-Reporting" target="_blank"><i class="fa fa-github" aria-hidden="true"></i></a> | .. also check <a class="foot" href="https://www.azadvertizer.net" target="_blank"><b>AzAdvertizer</b></a> to keep up with the pace on Azure Governance capabilities <b>|</b> <a class="foot" href="https://www.linkedin.com/in/julianhayward" target="_blank"><i class="fa fa-linkedin-square fa-sm" aria-hidden="true"></i></a>
    <hr>
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

$html | Set-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).html" -Encoding utf8 -Force
#endregion BuildHTML

#region BuildMD
$arrayMgs = @()
$arraySubs = @()
$markdown = $null
$markdownhierarchyMgs = $null
$markdownhierarchySubs = $null
$markdownTable = $null

if ($AzureDevOpsWikiAsCode) { 
$markdown += @"
# AzGovViz - Management Group Hierarchy

## Hierarchy Diagram (Mermaid)

::: mermaid
    graph TD;`n
"@
}
else{
$markdown += @"
# AzGovViz - Management Group Hierarchy

$executionDateTimeInternationalReadable ($currentTimeZone)

## Hierarchy Diagram (Mermaid)

::: mermaid
    graph TD;`n
"@
}

diagramMermaid

$markdown += @"
$markdownhierarchyMgs
$markdownhierarchySubs
 classDef mgr fill:#D9F0FF,stroke:#56595E,stroke-width:1px;
 classDef subs fill:#EEEEEE,stroke:#56595E,stroke-width:1px;
 classDef mgrprnts fill:#FFFFFF,stroke:#56595E,stroke-width:1px;
 class $(($arrayMgs | sort-object -unique) -join ",") mgr;
 class $(($arraySubs | sort-object -unique) -join ",") subs;
 class $mermaidprnts mgrprnts;
:::

## Hierarchy Table

| **MgLevel** | **MgName** | **MgId** | **MgParentName** | **MgParentId** | **SubName** | **SubId** |
|-------------|-------------|-------------|-------------|-------------|-------------|-------------|
$markdownTable
"@

$markdown | Set-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).md" -Encoding utf8 -Force
#endregion BuildMD

#endregion createoutputs

#endregion Code