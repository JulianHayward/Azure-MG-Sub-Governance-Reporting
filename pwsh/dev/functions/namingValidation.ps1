function NamingValidation($toCheck) {
    $checks = @(':', '/', '\', '<', '>', '|', '"')
    $array = [System.Collections.ArrayList]@()
    foreach ($check in $checks) {
        if ($toCheck -like "*$($check)*") {
            $null = $array.Add($check)
        }
    }
    if ($toCheck -match '\*') {
        $null = $array.Add('*')
    }
    if ($toCheck -match '\?') {
        $null = $array.Add('?')
    }
    return $array
}