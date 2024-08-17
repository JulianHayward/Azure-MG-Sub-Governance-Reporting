function createTagList {
    $startTagListArray = Get-Date
    Write-Host 'Creating TagList array'

    $tagsSubRgResCount = ($htAllTagList.'AllScopes'.Keys).Count
    $tagsSubsriptionCount = ($htAllTagList.'Subscription'.Keys).Count
    $tagsResourceGroupCount = ($htAllTagList.'ResourceGroup'.Keys).Count
    $tagsResourceCount = ($htAllTagList.'Resource'.Keys).Count
    Write-Host " Total Number of ALL unique Tag Names: $tagsSubRgResCount"
    Write-Host " Total Number of Subscription unique Tag Names: $tagsSubsriptionCount"
    Write-Host " Total Number of ResourceGroup unique Tag Names: $tagsResourceGroupCount"
    Write-Host " Total Number of Resource unique Tag Names: $tagsResourceCount"

    foreach ($tagScope in $htAllTagList.keys) {
        foreach ($tagScopeTagName in $htAllTagList.($tagScope).keys) {
            $null = $script:arrayTagList.Add([PSCustomObject]@{
                    Scope    = $tagScope
                    TagName  = ($tagScopeTagName)
                    TagCount = $htAllTagList.($tagScope).($tagScopeTagName)
                })
        }
    }
    $endTagListArray = Get-Date
    Write-Host "Creating TagList array duration: $((New-TimeSpan -Start $startTagListArray -End $endTagListArray).TotalMinutes) minutes ($((New-TimeSpan -Start $startTagListArray -End $endTagListArray).TotalSeconds) seconds)"
}