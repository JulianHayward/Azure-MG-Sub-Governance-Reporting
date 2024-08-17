function addIndexNumberToArray (
    [Parameter(Mandatory = $True)]
    [array]$array
) {
    for ($i = 0; $i -lt ($array).count; $i++) {
        Add-Member -InputObject $array[$i] -Name '#' -Value ($i + 1) -MemberType NoteProperty
    }
    return $array
}