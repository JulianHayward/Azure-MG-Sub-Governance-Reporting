#v6_major_20211018_1

#Wiki dir check
Write-Host "Wiki dir '$($env:WIKIDIR)' check"
if (-not (Test-Path -Path "$($env:SYSTEM_DEFAULTWORKINGDIRECTORY)/$($env:WIKIDIR)")) {
    #Assuming this is the initial run

    #Create the Wiki dir
    New-Item -ItemType Directory -Force -Path "$($env:SYSTEM_DEFAULTWORKINGDIRECTORY)/$($env:WIKIDIR)"

    #Repository permission check
    Write-Host "Repository access check"

    #createHeader
    $pat = $env:SYSTEM_ACCESSTOKEN #$(System.AccessToken)
    $token = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($pat)"))
    $header = @{authorization = "Basic $token" }

    $collectionUri = $env:SYSTEM_COLLECTIONURI #$(System.CollectionUri)
    $project = $env:SYSTEM_TEAMPROJECT #$(System.TeamProject)

    #region listRepos
    $uri = "$($collectionUri)/$($project)/_apis/git/repositories?api-version=5.1"
    $repos = Invoke-RestMethod -Uri $uri -Method "get" -Headers $header -ContentType "application/json"
    $htRepos = @{}
    foreach ($repo in $repos.value) {
        $htRepos.($repo.id) = @{}
        $htRepos.($repo.id).name = $repo.name
    }
    #endregion listRepos

    #region gettingSubjectDescriptor
    $organization = $collectionUri.Substring(0, $collectionUri.Length - 1) -replace ".*/"
    $buildServiceAccountId = $env:SYSTEM_TEAMPROJECTID #$(System.TeamProjectId)

    #either 'Project Collection Build Service ($($organization))' OR '$($project) Build Service ($($organization))'
    $buildAccount = "Project Collection Build Service ($($organization))"
    Write-Host "Checking: $buildAccount"
    $uri = "https://vssps.dev.azure.com/$($organization)/_apis/identities?searchFilter=General&filterValue=$($buildAccount)&queryMembership=None&api-version=6.0"
    $res = Invoke-RestMethod -Uri $uri -Method "GET" -Headers $header -ContentType "application/json"
    $providerDisplayName = $res.value.providerDisplayName
    $providerDisplayNameProjectCollectionBuildService = $providerDisplayName
    $subjectDescriptor = $res.value.subjectDescriptor

    if ($providerDisplayName -ne $buildServiceAccountId) {
        $buildAccount = "$($project) Build Service ($($organization))"
        Write-Host "Checking: $buildAccount"
        $uri = "https://vssps.dev.azure.com/$($organization)/_apis/identities?searchFilter=General&filterValue=$($buildAccount)&queryMembership=None&api-version=6.0"
        $res = Invoke-RestMethod -Uri $uri -Method "GET" -Headers $header -ContentType "application/json"
        $providerDisplayName = $res.value.providerDisplayName
        $providerDisplayNameProjectBuildService = $providerDisplayName
        $subjectDescriptor = $res.value.subjectDescriptor
    }
    #endregion gettingSubjectDescriptor

    if ($providerDisplayName -ne $buildServiceAccountId) {
        Write-Host "Neighter 'Project Collection Build Service ($($organization)) $($providerDisplayNameProjectCollectionBuildService)' nore '$($project) Build Service ($($organization))' $providerDisplayNameProjectBuildService matching Id: $($buildServiceAccountId)"
    }
    else {
        Write-Host "subjectDescriptor for '$($buildAccount)':" $subjectDescriptor

        #region gettingPermissions
        $repositoryId = $env:BUILD_REPOSITORY_ID #$(Build.Repository.ID)
        $permissionSetId = "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87" #Git Repositories

        $uri = "$($collectionUri)/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1"
        $body = @"
{
    "contributionIds": [
        "ms.vss-admin-web.security-view-permissions-data-provider"
    ],
    "dataProviderContext": {
        "properties": {
            "subjectDescriptor": "$($subjectDescriptor)",
            "permissionSetId": "$($permissionSetId)",
            "permissionSetToken": "repoV2/$($buildServiceAccountId)/$($repositoryId)"
        }
    }
}
"@

        $permissions = Invoke-RestMethod -Uri $uri -Method "post" -Body $body -Headers $header -ContentType "application/json"
        $htPermissionsRef = @{}
        $htPermissionsRef."1" = "allow"
        $htPermissionsRef."2" = "deny"
        $htPermissionsRef."3" = "allow(inherited)"
        Write-Host "'$($buildAccount)' ($buildServiceAccountId) permissions for Repository: $($htRepos.($repositoryId).name) ($repositoryId)"
        $contributePermissionState = ($permissions.dataProviders."ms.vss-admin-web.security-view-permissions-data-provider".subjectPermissions).where( { $_.displayName -eq "Contribute" } ).effectivePermissionValue
        if ($contributePermissionState -eq 1 -or $contributePermissionState -eq 3) {
            Write-Host " Contribute: $($htPermissionsRef."$contributePermissionState") ($($contributePermissionState))"
        }
        else {
            if ($contributePermissionState) {
                Write-Host " Contribute: $($htPermissionsRef."$contributePermissionState") ($($contributePermissionState))"
            }
            else {
                Write-Host " Contribute: not set"
            }
            $testResult = "FAILED"
        }
        Write-Host "All permissions:"
        foreach ($permission in $permissions.dataProviders."ms.vss-admin-web.security-view-permissions-data-provider".subjectPermissions) {
            if ($permission.effectivePermissionValue) {
                Write-Host " $($permission.displayName): $($htPermissionsRef."$($permission.effectivePermissionValue)") ($($permission.effectivePermissionValue))"
            }
            else {
                Write-Host " $($permission.displayName): not set"
            }
        }

        if ($testResult -eq "FAILED") {
            Write-Host ""
            Write-Host "- - - - - - - - - - - - - - - - -"
            Write-Host "Repository permission test failed"
            Write-Host "You must grant the Account '$($buildAccount)' ($buildServiceAccountId) with 'Contribute' permissions on the Repository '$($htRepos.($repositoryId).name)'' ($repositoryId)"
            Write-Host "Instructions: https://github.com/JulianHayward/Azure-MG-Sub-Governance-Reporting/blob/master/setup.md#grant-permissions-on-azgovviz-azdo-repository"
            Write-Error "Error"
        }
        else {
            $timestamp = get-date -format "yyyy-MM-dd_HH:mm:ss"
            $fileContent = @"
        Repository access check result:
        Date: $($timestamp)
        Build Account: '$($buildAccount)' ($buildServiceAccountId)
        Permission 'Contribute' for Repository '$($htRepos.($repositoryId).name) ($repositoryId)': $($contributePermissionState)
"@
            $fileContent | Set-Content -Path "$($env:SYSTEM_DEFAULTWORKINGDIRECTORY)/AzGovViz_RepositoryPermissionCheck.log" -Encoding utf8 -Force
        }
        #endregion gettingPermissions
    }
}
else {
    Write-Host "Wiki dir '$($env:WIKIDIR)' already exists"
}