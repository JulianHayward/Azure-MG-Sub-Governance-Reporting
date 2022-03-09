function getFileNaming {
    if ($Configuration['htParameters'].onAzureDevOpsOrGitHubActions -eq $true) {
        if ($Configuration['htParameters'].HierarchyMapOnly -eq $true) {
            $script:fileName = "AzGovViz_HierarchyMapOnly_$($ManagementGroupId)"
        }
        elseif ($Configuration['htParameters'].ManagementGroupsOnly -eq $true) {
            $script:fileName = "AzGovViz_ManagementGroupsOnly_$($ManagementGroupId)"
        }
        else {
            $script:fileName = "AzGovViz_$($ManagementGroupId)"
        }
    }
    else {
        if ($Configuration['htParameters'].HierarchyMapOnly -eq $true) {
            $script:fileName = "AzGovViz_HierarchyMapOnly_$($ProductVersion)_$($fileTimestamp)_$($ManagementGroupId)"
        }
        elseif ($Configuration['htParameters'].ManagementGroupsOnly -eq $true) {
            $script:fileName = "AzGovViz_ManagementGroupsOnly_$($ProductVersion)_$($fileTimestamp)_$($ManagementGroupId)"
        }
        else {
            $script:fileName = "AzGovViz_$($ProductVersion)_$($fileTimestamp)_$($ManagementGroupId)"
        }
    }
}