function getFileNaming {
    if ($htParameters.onAzureDevOpsOrGitHubActions -eq $true) {
        if ($htParameters.HierarchyMapOnly -eq $true) {
            $script:fileName = "AzGovViz_HierarchyMapOnly_$($ManagementGroupId)"
        }
        elseif ($htParameters.ManagementGroupsOnly -eq $true) {
            $script:fileName = "AzGovViz_ManagementGroupsOnly_$($ManagementGroupId)"
        }
        else {
            $script:fileName = "AzGovViz_$($ManagementGroupId)"
        }
    }
    else {
        if ($htParameters.HierarchyMapOnly -eq $true) {
            $script:fileName = "AzGovViz_HierarchyMapOnly_$($ProductVersion)_$($fileTimestamp)_$($ManagementGroupId)"
        }
        elseif ($htParameters.ManagementGroupsOnly -eq $true) {
            $script:fileName = "AzGovViz_ManagementGroupsOnly_$($ProductVersion)_$($fileTimestamp)_$($ManagementGroupId)"
        }
        else {
            $script:fileName = "AzGovViz_$($ProductVersion)_$($fileTimestamp)_$($ManagementGroupId)"
        }
    }
}