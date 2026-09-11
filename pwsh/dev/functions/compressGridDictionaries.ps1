function compressGridDictionaries {
    <#
    .SYNOPSIS
    Replaces the markup and resource id segments that the report repeats across thousands of AG Grid dictionary values
    (e.g. the AzAdvertizer link) with a single private use character that references the returned fragment table.
    The browser side counterpart 'agvExpandDictionaries' restores the values before the grid uses them.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]
        $Dictionaries
    )

    $gridDictionaryMarkupFragments = @(
        '<a class="externallink" href="https://www.azadvertizer.net/azpolicyadvertizer/'
        '<a class="externallink" href="https://www.azadvertizer.net/azpolicyinitiativesadvertizer/'
        '<a class="externallink" href="https://www.azadvertizer.net/azrolesadvertizer/'
        '.html" target="_blank" rel="noopener">'
        '</a>'
        '<b>'
        '</b>'
    )
    $gridDictionaryPathFragments = @(
        '/providers/microsoft.management/managementgroups/'
        '/providers/microsoft.authorization/policysetdefinitions/'
        '/providers/microsoft.authorization/policydefinitions/'
        '/providers/microsoft.authorization/policyassignments/'
        '/providers/microsoft.authorization/policyexemptions/'
        '/providers/microsoft.authorization/roledefinitions/'
        '/providers/microsoft.authorization/roleassignments/'
        '/subscriptions/'
        '/resourcegroups/'
    )
    $gridDictionaryFragments = @($gridDictionaryMarkupFragments) + @($gridDictionaryPathFragments)
    $gridDictionaryMarkupFragmentsCount = $gridDictionaryMarkupFragments.Count
    $gridDictionaryFragmentsCount = $gridDictionaryFragments.Count

    #private use area, json keeps those characters as is and Azure data does not contain them
    $gridDictionaryTokens = New-Object 'string[]' $gridDictionaryFragmentsCount
    for ($fragmentIndex = 0; $fragmentIndex -lt $gridDictionaryFragmentsCount; $fragmentIndex++) {
        $gridDictionaryTokens[$fragmentIndex] = [string][char](0xE000 + $fragmentIndex)
    }

    foreach ($dictionary in $Dictionaries) {
        for ($valueIndex = 0; $valueIndex -lt $dictionary.Count; $valueIndex++) {
            $value = $dictionary[$valueIndex]
            if ([string]::IsNullOrEmpty($value)) {
                continue
            }
            #the markup must go first, its href would otherwise be hit by the path fragments
            if ($value.IndexOf('<') -ge 0) {
                for ($fragmentIndex = 0; $fragmentIndex -lt $gridDictionaryMarkupFragmentsCount; $fragmentIndex++) {
                    $value = $value.Replace($gridDictionaryFragments[$fragmentIndex], $gridDictionaryTokens[$fragmentIndex])
                }
            }
            if ($value.IndexOf('/') -ge 0) {
                for ($fragmentIndex = $gridDictionaryMarkupFragmentsCount; $fragmentIndex -lt $gridDictionaryFragmentsCount; $fragmentIndex++) {
                    $value = $value.Replace($gridDictionaryFragments[$fragmentIndex], $gridDictionaryTokens[$fragmentIndex])
                }
            }
            $dictionary[$valueIndex] = $value
        }
    }

    return [PSCustomObject]@{
        dictionaries = $Dictionaries
        fragments    = $gridDictionaryFragments
    }
}
