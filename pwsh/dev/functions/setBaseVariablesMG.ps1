function setBaseVariablesMG {
    if (($azAPICallConf['checkContext']).Tenant.Id -ne $ManagementGroupId) {
        $script:mgSubPathTopMg = $selectedManagementGroupId.ParentName
        $script:getMgParentId = $selectedManagementGroupId.ParentName
        $script:getMgParentName = $selectedManagementGroupId.ParentDisplayName
        $script:mermaidprnts = "'$(($azAPICallConf['checkContext']).Tenant.Id)',$getMgParentId"
    }
    else {
        $script:hierarchyLevel = -1
        $script:mgSubPathTopMg = "$ManagementGroupId"
        $script:getMgParentId = "'$ManagementGroupId'"
        $script:getMgParentName = 'Tenant Root'
        $script:mermaidprnts = "'$getMgParentId',$getMgParentId"
    }
}