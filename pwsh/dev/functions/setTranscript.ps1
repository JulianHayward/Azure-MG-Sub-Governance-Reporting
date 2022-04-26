function setTranscript {
    if ($ManagementGroupId) {
        if ($onAzureDevOpsOrGitHubActions -eq $true) {
            if ($HierarchyMapOnly -eq $true) {
                $script:fileNameTranscript = "AzGovViz_HierarchyMapOnly_$($ManagementGroupId)_Log.txt"
            }
            elseif ($ManagementGroupsOnly -eq $true) {
                $script:fileNameTranscript = "AzGovViz_ManagementGroupsOnly_$($ManagementGroupId)_Log.txt"
            }
            else {
                $script:fileNameTranscript = "AzGovViz_$($ManagementGroupId)_Log.txt"
            }
        }
        else {
            if ($HierarchyMapOnly -eq $true) {
                $script:fileNameTranscript = "AzGovViz_HierarchyMapOnly_$($ProductVersion)_$($fileTimestamp)_$($ManagementGroupId)_Log.txt"
            }
            elseif ($ManagementGroupsOnly -eq $true) {
                $script:fileNameTranscript = "AzGovViz_ManagementGroupsOnly_$($ProductVersion)_$($fileTimestamp)_$($ManagementGroupId)_Log.txt"
            }
            else {
                $script:fileNameTranscript = "AzGovViz_$($ProductVersion)_$($fileTimestamp)_$($ManagementGroupId)_Log.txt"
            }
        }
    }
    else {
        if ($onAzureDevOpsOrGitHubActions -eq $true) {
            if ($HierarchyMapOnly -eq $true) {
                $script:fileNameTranscript = 'AzGovViz_HierarchyMapOnly_Log.txt'
            }
            elseif ($ManagementGroupsOnly -eq $true) {
                $script:fileNameTranscript = 'AzGovViz_ManagementGroupsOnly_Log.txt'
            }
            else {
                $script:fileNameTranscript = 'AzGovViz_Log.txt'
            }
        }
        else {
            if ($HierarchyMapOnly -eq $true) {
                $script:fileNameTranscript = "AzGovViz_HierarchyMapOnly_$($ProductVersion)_$($fileTimestamp)_Log.txt"
            }
            elseif ($ManagementGroupsOnly -eq $true) {
                $script:fileNameTranscript = "AzGovViz_ManagementGroupsOnly_$($ProductVersion)_$($fileTimestamp)_Log.txt"
            }
            else {
                $script:fileNameTranscript = "AzGovViz_$($ProductVersion)_$($fileTimestamp)_Log.txt"
            }
        }
    }
    Write-Host "Writing transcript: $($outputPath)$($DirectorySeparatorChar)$($fileNameTranscript)"
    Start-Transcript -Path "$($outputPath)$($DirectorySeparatorChar)$($fileNameTranscript)"
}