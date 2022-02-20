#region CheckCodeRunPlatform
$onAzureDevOps = $false
$onAzureDevOpsOrGitHubActions = $false
if ($env:GITHUB_SERVER_URL -and $env:CODESPACES) {
    $checkCodeRunPlatform = "GitHubCodespaces"
}
elseif ($env:REMOTE_CONTAINERS) {
    $checkCodeRunPlatform = "RemoteContainers"
}
elseif ($env:SYSTEM_TEAMPROJECTID -and $env:BUILD_REPOSITORY_ID) {
    $checkCodeRunPlatform = "AzureDevOps"
    $onAzureDevOps = $true
    $onAzureDevOpsOrGitHubActions = $true
}
elseif ($PSPrivateMetadata) {
    $checkCodeRunPlatform = "AzureAutomation"
}
elseif ($env:GITHUB_ACTIONS) {
    $checkCodeRunPlatform = "GitHubActions"
    $onAzureDevOpsOrGitHubActions = $true
}
elseif ($env:ACC_IDLE_TIME_LIMIT -and $env:AZURE_HTTP_USER_AGENT -and $env:AZUREPS_HOST_ENVIRONMENT) {
    $checkCodeRunPlatform = "CloudShell"
}
else {
    $checkCodeRunPlatform = "Console"
}
#endregion CheckCodeRunPlatform
Write-Host "CheckCodeRunPlatform:" $checkCodeRunPlatform

if ($DebugAzAPICall) {
    write-host "AzAPICall debug enabled" -ForegroundColor Cyan
}
else {
    write-host "AzAPICall debug disabled" -ForegroundColor Cyan
}

#Region Test-HashtableParameter
$htParameters = @{
    GitHubRepository = $GitHubRepository
    DebugAzAPICall  = [bool]$DebugAzAPICall
    CodeRunPlatform = $checkCodeRunPlatform
    onAzureDevOps = $onAzureDevOps
    onAzureDevOpsOrGitHubActions = $onAzureDevOpsOrGitHubActions
}
#EndRegion Test-HashtableParameter