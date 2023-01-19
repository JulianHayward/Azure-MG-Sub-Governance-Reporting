function getFileNaming {
    if ($azAPICallConf['htParameters'].onAzureDevOpsOrGitHubActions -eq $true) {
        if ($HierarchyMapOnly) {
            $script:fileName = "AzGovViz_HierarchyMapOnly_$($ManagementGroupId)"
        }
        elseif ($azAPICallConf['htParameters'].ManagementGroupsOnly -eq $true) {
            $script:fileName = "AzGovViz_ManagementGroupsOnly_$($ManagementGroupId)"
        }
        else {
            $script:fileName = "AzGovViz_$($ManagementGroupId)"
        }
    }
    else {
        if ($HierarchyMapOnly) {
            $script:fileName = "AzGovViz_HierarchyMapOnly_$($ProductVersion)_$($fileTimestamp)_$($ManagementGroupId)"
        }
        elseif ($azAPICallConf['htParameters'].ManagementGroupsOnly -eq $true) {
            $script:fileName = "AzGovViz_ManagementGroupsOnly_$($ProductVersion)_$($fileTimestamp)_$($ManagementGroupId)"
        }
        else {
            $script:fileName = "AzGovViz_$($ProductVersion)_$($fileTimestamp)_$($ManagementGroupId)"
        }
    }
}