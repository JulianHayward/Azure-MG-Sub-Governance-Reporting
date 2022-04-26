function NamingValidation($toCheck) {
    $checks = @(':', '/', '\', '<', '>', '|', '"')
    $array = @()
    foreach ($check in $checks) {
        if ($toCheck -like "*$($check)*") {
            $array += $check
        }
    }
    if ($toCheck -match '\*') {
        $array += '*'
    }
    if ($toCheck -match '\?') {
        $array += '?'
    }
    return $array
}